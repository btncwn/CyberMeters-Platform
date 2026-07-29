import { isPublishableModuleEvidence } from "./scan-budget.js";
import {
  normalizeQuality,
  resolveAssessmentPresentation,
  SCAN_QUALITY,
} from "./assessment-presentation.js";

export const PHASE5_EVIDENCE_MODULES = Object.freeze({
  cve: "cve_intelligence",
  kev: "known_exploited_vulnerabilities",
  email: "email_security_intelligence",
});

export const PHASE5_INCOMPLETE_REASON = "phase5_evidence_incomplete";
export const PHASE5_MISSING_EVIDENCE_REASON = "historical_module_evidence_missing";

function missingPhase5Evidence(moduleKey) {
  return {
    executed: false,
    incomplete: true,
    outcome: "unavailable",
    reason: PHASE5_MISSING_EVIDENCE_REASON,
    source: moduleKey,
    evidence_publishable: false,
  };
}

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
    } else {
      // Historical reports may pre-date one or more Phase-5 modules. Absence is
      // explicitly projected as unavailable evidence; it is never an empty,
      // successfully measured result.
      projected[moduleKey] = missingPhase5Evidence(moduleKey);
    }
  }
  return projected;
}

function incompleteCustomerQuality(scanQuality) {
  return normalizeQuality(scanQuality) === SCAN_QUALITY.DEGRADED
    ? SCAN_QUALITY.DEGRADED
    : SCAN_QUALITY.PARTIAL;
}

/**
 * Canonical read-time projection for a stored assessment.
 *
 * Stored R2/D1/snapshot facts remain immutable. This derives the assessment
 * customers may currently be shown from the same Phase-5 completeness contract
 * used at scan finalisation.
 */
export function resolvePhase5HistoricalCustomerProjection({
  score = null,
  riskLevel = null,
  assessment = null,
  scanQuality = null,
  modules = {},
} = {}) {
  const customer = resolvePhase5CustomerAssessment({ score, riskLevel, modules });
  if (customer.evidence.complete) {
    return {
      ...customer,
      scan_quality: normalizeQuality(scanQuality),
      assessment,
    };
  }

  const quality = incompleteCustomerQuality(scanQuality);
  return {
    ...customer,
    scan_quality: quality,
    assessment: resolveAssessmentPresentation({
      score: null,
      scanQuality: quality,
      status: "completed",
      coverage: {
        reason: PHASE5_INCOMPLETE_REASON,
        incomplete_modules: customer.evidence.incomplete_modules,
      },
    }),
  };
}

export function projectPhase5RiskIntelligenceForCustomer(riskIntelligence, evidence) {
  if (!riskIntelligence || typeof riskIntelligence !== "object") return riskIntelligence ?? null;
  if (evidence?.complete === true) return riskIntelligence;
  return {
    ...riskIntelligence,
    overall_risk_level: null,
    narrative: null,
    incomplete: true,
    incomplete_reason: PHASE5_INCOMPLETE_REASON,
  };
}

/**
 * Customer renderer view of an immutable snapshot. The input object is never
 * mutated and remains available on read.snapshot for checksum/verbatim APIs.
 */
export function projectPhase5SnapshotForCustomer(snapshot, modules = {}) {
  const overall = snapshot?.overall ?? {};
  const projection = resolvePhase5HistoricalCustomerProjection({
    score: overall.cyber_metrics_score,
    riskLevel: overall.score_band,
    assessment: overall.assessment ?? null,
    scanQuality:
      overall.assessment?.quality ??
      overall.evidence_completeness?.scan_quality ??
      null,
    modules,
  });
  if (projection.evidence.complete) return snapshot;

  const bri = overall.business_risk_indicator ?? {};
  return {
    ...snapshot,
    overall: {
      ...overall,
      cyber_metrics_score: null,
      score_band: null,
      assessment: projection.assessment,
      summary: null,
      business_risk_indicator: {
        ...bri,
        band: null,
        explanation: null,
        provisional: true,
        internal_metrics: {
          ...(bri.internal_metrics ?? {}),
          score: null,
        },
      },
      evidence_completeness: {
        ...(overall.evidence_completeness ?? {}),
        scan_quality: projection.scan_quality,
        assessment_quality: projection.scan_quality,
        phase5_evidence: projection.evidence,
      },
      not_fully_assessed: [
        ...new Set([
          ...(Array.isArray(overall.not_fully_assessed) ? overall.not_fully_assessed : []),
          ...projection.evidence.incomplete_modules,
        ]),
      ],
    },
  };
}

async function readStoredPhase5Modules(env, scanId) {
  if (!env?.cybermeters_reports || !scanId) return {};
  try {
    const object = await env.cybermeters_reports.get(`reports/${scanId}.json`);
    const report = object ? await object.json() : null;
    return report?.modules && typeof report.modules === "object" ? report.modules : {};
  } catch {
    return {};
  }
}

/**
 * Bounded read-time adapter for D1 scan rows. It performs no writes and removes
 * score/rating unless the referenced immutable report explicitly proves every
 * required Phase-5 module publishable.
 */
export async function projectPhase5ScanRowsForCustomer(env, rows = []) {
  const projected = await Promise.all((rows ?? []).map(async (row) => {
    if (!row || row.status !== "completed") return row;
    const modules = await readStoredPhase5Modules(env, row.id ?? row.scan_id);
    const customer = resolvePhase5HistoricalCustomerProjection({
      score: row.score,
      riskLevel: row.rating,
      scanQuality: row.scan_quality,
      modules,
    });
    return {
      ...row,
      score: customer.score,
      rating: customer.risk_level,
      scan_quality: customer.scan_quality,
      assessment: customer.assessment,
      phase5_evidence: customer.evidence,
    };
  }));
  return projected;
}
