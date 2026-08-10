// ── Customer alert evidence-fidelity projection ─────────────────────────────
//
// This module owns presentation only. It receives the SSL module's already-
// canonical result and never inspects HTTP responses, status codes, provider
// errors or timeouts. PR-A1/PR-A2 own that classification; the shared scan-budget
// contract owns whether a module result is publishable evidence.
//
// The resolver returns one coherent subject/body/action decision. Callers must
// not select those fields independently, because that is how an uncertain
// transport observation acquired a certificate-install subject and action.
import { isPublishableModuleEvidence } from "./scan-budget.js";
import { resolveTlsRuntimeState, TLS_RUNTIME_STATES } from "./tls-evidence.js";

const HTTPS_REVIEW_ACTION =
  "Review the available evidence and run another assessment. If the result persists, verify HTTPS availability with your hosting provider.";

const HTTPS_UNCERTAIN = Object.freeze({
  title: "HTTPS could not be verified",
  what_changed: "CyberMeters could not complete an HTTPS/TLS observation during this assessment.",
  recommended_action: HTTPS_REVIEW_ACTION,
  remediation_id: null,
  presentation_state: "observation_unavailable",
});

const REDIRECT_UNCERTAIN = Object.freeze({
  title: "HTTP-to-HTTPS redirect could not be verified",
  what_changed: "CyberMeters could not complete the HTTP-to-HTTPS redirect observation during this assessment.",
  recommended_action: HTTPS_REVIEW_ACTION,
  remediation_id: null,
  presentation_state: "observation_unavailable",
});

const HTTPS_CONFLICT = Object.freeze({
  title: "HTTPS evidence requires review",
  what_changed: "CyberMeters observed conflicting HTTPS/TLS evidence during this assessment and could not confirm the reported transport condition.",
  recommended_action: "Review the alert evidence and run another assessment. If the conflict persists, verify the site configuration with your hosting provider.",
  remediation_id: null,
  presentation_state: "evidence_conflict",
});

const REDIRECT_CONFLICT = Object.freeze({
  title: "HTTP-to-HTTPS redirect evidence requires review",
  what_changed: "CyberMeters observed conflicting HTTP-to-HTTPS redirect evidence during this assessment and could not confirm the reported redirect condition.",
  recommended_action: "Review the alert evidence and run another assessment. If the conflict persists, verify the redirect configuration with your hosting provider.",
  remediation_id: null,
  presentation_state: "evidence_conflict",
});

function observationState(moduleEvidence, findingType) {
  if (findingType === "ssl_no_http_redirect" || findingType === "no_https_redirect") {
    return moduleEvidence?.http_redirect_chain?.observation_state
      || moduleEvidence?.http_redirect_chain?.observation_completeness
      || "not_assessed";
  }
  return moduleEvidence?.https_observation_state
    || moduleEvidence?.https_observation_completeness
    || "not_assessed";
}

function canonicalResult(canonical, state) {
  return {
    title: canonical?.title || "Review this alert",
    what_changed: canonical?.what_changed || "A monitored condition changed.",
    recommended_action: canonical?.recommended_action || "Review this alert in CyberMeters.",
    remediation_id: canonical?.remediation_id || null,
    presentation_state: state,
  };
}

/**
 * Resolve the customer-facing meaning of one managed alert.
 *
 * `module_evidence` is the canonical module result already produced by the scan
 * engine. This function intentionally has no raw-response inputs.
 */
export function resolveCustomerAlertPresentation({
  domain_key,
  recurrence,
  finding_type,
  module_evidence = null,
  canonical = null,
} = {}) {
  if (String(domain_key || "") !== "website_security") {
    return canonicalResult(canonical, "canonical_finding");
  }

  const type = String(finding_type || "");
  const rec = String(recurrence || "");
  const certificateCondition =
    rec === "transport_not_available"
    || type === "ssl_not_available"
    || type === "ssl_no_certificate";
  const redirectCondition =
    rec === "insecure_redirect"
    || type === "ssl_no_http_redirect"
    || type === "no_https_redirect";

  if (!certificateCondition && !redirectCondition) {
    return canonicalResult(canonical, "canonical_finding");
  }

  const publishable = isPublishableModuleEvidence(module_evidence);
  if (certificateCondition) {
    const tls = resolveTlsRuntimeState(module_evidence);
    if (publishable && tls.state === TLS_RUNTIME_STATES.POSITIVELY_ABSENT) {
      return canonicalResult(canonical, "positively_observed_certificate_defect");
    }
    // A completed healthy observation contradicting an eligible lifecycle
    // occurrence is surfaced as an explicit evidence conflict. Presentation must
    // never suppress the occurrence: conflict is visible, bounded and reviewable.
    if (publishable && tls.state === TLS_RUNTIME_STATES.OBSERVED_PRESENT) {
      return {
        ...HTTPS_CONFLICT,
        evidence_state: observationState(module_evidence, type),
      };
    }
    return {
      ...HTTPS_UNCERTAIN,
      evidence_state: observationState(module_evidence, type),
    };
  }

  const chain = module_evidence?.http_redirect_chain;
  const redirectObserved =
    chain?.observation_state === "origin_response"
    || (!chain?.observation_state && chain?.http_redirect_validated === true);
  if (
    publishable
    && module_evidence?.http_redirects_to_https === false
    && chain?.http_redirect_validated === true
    && redirectObserved
  ) {
    return canonicalResult(canonical, "positively_observed_redirect_defect");
  }
  if (publishable && module_evidence?.http_redirects_to_https === true) {
    return {
      ...REDIRECT_CONFLICT,
      evidence_state: observationState(module_evidence, type),
    };
  }
  return {
    ...REDIRECT_UNCERTAIN,
    evidence_state: observationState(module_evidence, type),
  };
}
