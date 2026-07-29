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

const HTTPS_REVIEW_ACTION =
  "Review the available evidence and run another assessment. If the result persists, verify HTTPS availability with your hosting provider.";

const HTTPS_UNCERTAIN = Object.freeze({
  title: "HTTPS could not be verified",
  what_changed: "CyberMeters could not complete an HTTPS/TLS observation during this assessment.",
  recommended_action: HTTPS_REVIEW_ACTION,
  remediation_id: null,
  presentation_state: "observation_unavailable",
  publish: true,
});

const REDIRECT_UNCERTAIN = Object.freeze({
  title: "HTTP-to-HTTPS redirect could not be verified",
  what_changed: "CyberMeters could not complete the HTTP-to-HTTPS redirect observation during this assessment.",
  recommended_action: HTTPS_REVIEW_ACTION,
  remediation_id: null,
  presentation_state: "observation_unavailable",
  publish: true,
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
    publish: true,
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
    if (publishable && module_evidence?.https_available === false) {
      return canonicalResult(canonical, "positively_observed_certificate_defect");
    }
    // A completed healthy observation can never be converted into an uncertainty
    // warning. This is a contradiction guard only; the canonical finding/lifecycle
    // gates prevent this combination on the normal path.
    if (publishable && module_evidence?.https_available === true) {
      return {
        ...canonicalResult(canonical, "positively_observed_healthy"),
        publish: false,
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
      ...canonicalResult(canonical, "positively_observed_healthy"),
      publish: false,
    };
  }
  return {
    ...REDIRECT_UNCERTAIN,
    evidence_state: observationState(module_evidence, type),
  };
}
