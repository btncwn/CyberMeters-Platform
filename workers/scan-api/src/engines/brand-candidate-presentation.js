import { resolveCyberMotDomainStates } from "./cyber-mot-domains.js";

const CANDIDATE_TITLE = "Unvalidated lookalike candidate on the watchlist";
const CANDIDATE_EXPLANATION =
  "This name is a candidate only. Registration, activity, and abuse have not been confirmed.";

function unvalidatedBrandFinding(finding) {
  return /^brand_/.test(finding?.id || "") || finding?.module === "brand_monitoring";
}

export function hasUnvalidatedBrandFinding(report) {
  return report?.modules?.brand_monitoring?.candidates_validated !== true &&
    Array.isArray(report?.findings) && report.findings.some((finding) =>
      unvalidatedBrandFinding(finding) && finding?.finding_type !== "observation");
}

export function projectUnvalidatedBrandReportForCustomer(report) {
  if (!report || report?.modules?.brand_monitoring?.candidates_validated === true) return report;
  return {
    ...report,
    findings: (Array.isArray(report.findings) ? report.findings : []).map((finding) =>
      unvalidatedBrandFinding(finding)
        ? {
            ...finding,
            finding_type: "observation",
            severity: "info",
            score_impact: 0,
            title: CANDIDATE_TITLE,
            description: CANDIDATE_EXPLANATION,
            recommendation: null,
            evidence: (Array.isArray(finding.evidence) ? finding.evidence : [])
              .filter((item) => !/risk level/i.test(String(item?.label || ""))),
            unvalidated_brand_candidate: true,
          }
        : finding),
  };
}

export function projectUnvalidatedBrandSnapshotForCustomer(snapshot, sourceReport) {
  const candidateValidation = sourceReport?.modules?.brand_monitoring?.candidates_validated;
  const sourceUnavailable = candidateValidation !== true && candidateValidation !== false;
  if (candidateValidation === true) return snapshot;
  const brand = sourceUnavailable
    ? (snapshot?.domains || []).some((entry) => entry.domain_key === "brand_protection")
      ? { state: "evidence_insufficient", summary: "Brand evidence is unavailable for this report." }
      : null
    : resolveCyberMotDomainStates(
      projectUnvalidatedBrandReportForCustomer(sourceReport),
    ).find((entry) => entry.domain_key === "brand_protection");
  if (!brand) return snapshot;
  const domains = (Array.isArray(snapshot?.domains) ? snapshot.domains : []).map((entry) =>
    entry.domain_key === "brand_protection"
      ? {
          ...entry, state: brand.state, coverage: brand.coverage,
          summary: brand.summary, state_reason: brand.summary,
          finding_count: 0, finding_ids: [], highest_severity: null,
          recommendation_count: 0,
        }
      : entry);
  const converted = [];
  const observedFindings = (Array.isArray(snapshot?.observed_findings) ? snapshot.observed_findings : [])
    .filter((item) => {
      if (!/^brand_/.test(item?.finding_id || "") && !item?.domain_keys?.includes("brand_protection")) return true;
      converted.push({
        ...item, finding_type: "observation", severity: "info", score_impact: 0,
        title: CANDIDATE_TITLE, explanation: CANDIDATE_EXPLANATION,
        remediation_id: null, remediation_title: null, remediation_action: null,
        verification_method: null, verification_support: null,
      });
      return false;
    });
  const convertedIds = new Set(converted.map((item) => item.finding_id).filter(Boolean));
  const remediationActions = (Array.isArray(snapshot?.remediation_actions) ? snapshot.remediation_actions : [])
    .filter((action) => !(Array.isArray(action.finding_ids) &&
      action.finding_ids.length > 0 && action.finding_ids.every((id) => convertedIds.has(id))));
  const healthy = domains.filter((entry) => entry.state === "assessed_healthy").length;
  const issues = domains.filter((entry) => entry.state === "issue_detected").length;
  const attention = domains.length - healthy - issues;
  const notFullyAssessed = (Array.isArray(snapshot?.overall?.not_fully_assessed)
    ? snapshot.overall.not_fully_assessed : []).filter((entry) => entry.domain_key !== "brand_protection");
  if (!["assessed_healthy", "issue_detected"].includes(brand.state)) {
    notFullyAssessed.push({ domain_key: "brand_protection", state: brand.state, reason: brand.summary });
  }
  return {
    ...snapshot, domains, observed_findings: observedFindings,
    observations: [...(Array.isArray(snapshot?.observations) ? snapshot.observations : []), ...converted],
    remediation_actions: remediationActions,
    overall: {
      ...snapshot.overall,
      summary: snapshot?.overall?.summary == null ? null
        : `Across the eight Cyber MOT domains: ${healthy} assessed healthy, ${issues} with issues detected, and ${attention} needing further evidence, customer input or monitoring.`,
      not_fully_assessed: notFullyAssessed,
      ...((!sourceReport || (sourceUnavailable && converted.length > 0) || hasUnvalidatedBrandFinding(sourceReport)) ? {
        cyber_metrics_score: null,
        score_band: null,
        assessment: snapshot?.overall?.assessment
          ? {
              ...snapshot.overall.assessment,
              raw_score: null, display_score: null, display_rating: null,
              state: "not_established", provisional: true,
              authoritative: false, comparable: false,
              message: "The stored brand assessment needs validation before its score can be shown.",
              suppression_reason: "unvalidated_brand_candidate",
            }
          : null,
        business_risk_indicator: snapshot?.overall?.business_risk_indicator
          ? {
              ...snapshot.overall.business_risk_indicator, band: null, provisional: true,
              explanation: "The stored assessment included an unvalidated lookalike candidate, so its risk indicator is not authoritative.",
              internal_metrics: null,
            }
          : null,
      } : {}),
    },
  };
}
