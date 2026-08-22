import { isPublishableModuleEvidence } from "./scan-budget.js";
import {
  normalizeQuality,
  resolveAssessmentPresentation,
  SCAN_QUALITY,
} from "./assessment-presentation.js";
import {
  projectTlsModulesForCustomer,
  projectTlsSnapshotForCustomer,
  resolveTlsRuntimeState,
  TLS_RUNTIME_STATES,
} from "./tls-evidence.js";
import { buildIdentityEvidenceProjection, summarizeIdentityClaims } from "./identity-evidence-contract.js";
import { isResolverVersionAtLeast, FIRST_HONEST_RESOLVER_VERSION } from "./cyber-mot-domains.js";
// READ-ONLY consumption of the canonical authority. `lib/serviceability.js` belongs
// to the #422 lane and is NOT edited here; importing it is what keeps the historical
// read projection and the live producer deciding serviceability the same way.
import { classifyServiceability, maySupportDefectConclusion } from "../lib/serviceability.js";

export const PHASE5_EVIDENCE_MODULES = Object.freeze({
  cve: "cve_intelligence",
  kev: "known_exploited_vulnerabilities",
  email: "email_security_intelligence",
});

export const PHASE5_INCOMPLETE_REASON = "phase5_evidence_incomplete";
export const PHASE5_MISSING_EVIDENCE_REASON = "historical_module_evidence_missing";
export const PHASE5_EVIDENCE_READ_CONCURRENCY = 8;
export const PHASE5_EVIDENCE_READ_LIMIT = 100;
export const PHASE5_EVIDENCE_READ_CONTRACT =
  "phase5-historical-evidence-read-v1";

export const CVE_COVERAGE_STATES = Object.freeze([
  "complete",
  "partial",
  "unavailable",
  "dependency_unavailable",
  "not_applicable",
]);

export const CVE_CUSTOMER_MESSAGES = Object.freeze({
  provider_unavailable:
    "CyberMeters could not complete the vulnerability assessment because the required CVE evidence was unavailable.",
  partial_positive:
    "The vulnerability assessment is incomplete. Confirmed findings are shown, but some CVE checks could not be completed.",
  dependency_unavailable:
    "CyberMeters could not complete the vulnerability assessment because technology detection did not complete.",
  historical_unknown:
    "This historical vulnerability assessment is unavailable because its evidence coverage was not recorded.",
});

const CVE_COMPLETE_NEGATIVE_STATES = new Set(["complete", "not_applicable"]);

export function resolveCveCoverage(moduleResult) {
  const value = moduleResult?.cve_coverage;
  return CVE_COVERAGE_STATES.includes(value) ? value : "unknown";
}

function cveLookupCompleted(row) {
  return ["complete", "available", "completed"].includes(row?.status);
}

function hasMeasuredCvePositive(moduleResult) {
  if (!moduleResult || typeof moduleResult !== "object") return false;
  return Object.entries(moduleResult.results ?? {}).some(([technology, rows]) =>
    cveLookupCompleted(moduleResult.lookup_statuses?.[technology]) &&
    Array.isArray(rows) && rows.length > 0
  );
}

function resolveCveEvidence(moduleResult) {
  const coverage = resolveCveCoverage(moduleResult);
  const carrierUsable = !!moduleResult && typeof moduleResult === "object" &&
    !moduleResult.error && moduleResult.skipped !== true &&
    moduleResult.executed !== false && moduleResult.outcome !== "deadline_exceeded";
  const negative_complete = carrierUsable &&
    CVE_COMPLETE_NEGATIVE_STATES.has(coverage) &&
    moduleResult.incomplete !== true;
  const positive_publishable = carrierUsable && (
    negative_complete ||
    (coverage === "partial" && hasMeasuredCvePositive(moduleResult))
  );
  return { coverage, negative_complete, positive_publishable };
}

function cveCustomerMessage(moduleResult) {
  switch (resolveCveCoverage(moduleResult)) {
    case "unavailable":
      return CVE_CUSTOMER_MESSAGES.provider_unavailable;
    case "partial":
      return CVE_CUSTOMER_MESSAGES.partial_positive;
    case "dependency_unavailable":
      return CVE_CUSTOMER_MESSAGES.dependency_unavailable;
    case "unknown":
      return CVE_CUSTOMER_MESSAGES.historical_unknown;
    default:
      return null;
  }
}

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
  const tls = resolveTlsRuntimeState(modules?.ssl);
  const unsupportedTlsAbsence = modules?.ssl?.https_available === false
    && tls.state === TLS_RUNTIME_STATES.UNAVAILABLE;
  const cveEvidence = resolveCveEvidence(
    modules?.[PHASE5_EVIDENCE_MODULES.cve],
  );
  const publishable = {
    cve: cveEvidence.positive_publishable,
    kev: isPublishableModuleEvidence(modules?.[PHASE5_EVIDENCE_MODULES.kev]),
    email: isPublishableModuleEvidence(modules?.[PHASE5_EVIDENCE_MODULES.email]),
  };
  const completeByModule = {
    cve: cveEvidence.negative_complete,
    kev: publishable.kev,
    email: publishable.email,
  };
  const incompleteModules = Object.entries(PHASE5_EVIDENCE_MODULES)
    .filter(([name]) => !completeByModule[name])
    .map(([, moduleKey]) => moduleKey);
  if (unsupportedTlsAbsence) incompleteModules.push("ssl");
  return {
    complete: incompleteModules.length === 0,
    publishable,
    coverage_complete: completeByModule,
    cve_coverage: cveEvidence.coverage,
    incomplete_modules: incompleteModules,
    tls_state: tls.state,
    unsupported_tls_absence: unsupportedTlsAbsence,
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
  const projected = projectTlsModulesForCustomer(modules);
  const identity = projected.identity_discovery;
  if (identity && typeof identity === "object") {
    const projectItem = (item) => {
      const projection = buildIdentityEvidenceProjection({
        ...item,
        evidence: typeof item?.evidence === "string" ? item.evidence : JSON.stringify(item?.evidence ?? []),
      });
      return { ...item, ...projection };
    };
    const providers = (Array.isArray(identity.providers) ? identity.providers : []).map(projectItem);
    const portals = (Array.isArray(identity.portals) ? identity.portals : []).map(projectItem);
    projected.identity_discovery = {
      ...identity,
      providers,
      portals,
      ...summarizeIdentityClaims([...providers, ...portals]),
      reachability_status: "not_evaluated",
      reachability_reason: "no_supported_reachability_producer",
    };
  }
  for (const [name, moduleKey] of Object.entries(PHASE5_EVIDENCE_MODULES)) {
    const value = modules?.[moduleKey];
    if (value && typeof value === "object") {
      const cveProjection = name === "cve"
        ? {
            cve_coverage: evidence.cve_coverage,
            evidence_complete: evidence.coverage_complete.cve,
            total_count_publishable: evidence.coverage_complete.cve,
            customer_message: cveCustomerMessage(value),
            lookup_presentations: Object.fromEntries(
              (value.technologies_checked ?? []).map((technology) => {
                const measured = cveLookupCompleted(
                  value.lookup_statuses?.[technology],
                );
                return [technology, {
                  evidence_publishable: measured,
                  customer_message: measured
                    ? null
                    : "CyberMeters could not retrieve CVE evidence for this technology.",
                }];
              }),
            ),
          }
        : {};
      projected[moduleKey] = {
        ...value,
        evidence_publishable: evidence.publishable[name],
        ...cveProjection,
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
  monitoringStates = undefined,
} = {}) {
  const customer = resolvePhase5CustomerAssessment({ score, riskLevel, modules });
  if (customer.evidence.complete) {
    return {
      ...customer,
      scan_quality: normalizeQuality(scanQuality),
      assessment: assessment ?? resolveAssessmentPresentation({
        score: customer.score,
        scanQuality,
        status: "completed",
        ...(monitoringStates !== undefined
          ? { monitoringStates, requireMonitoring: true }
          : {}),
      }),
    };
  }

  const quality = incompleteCustomerQuality(scanQuality);
  const message = cveCustomerMessage(modules?.cve_intelligence);
  return {
    ...customer,
    scan_quality: quality,
    assessment: {
      ...resolveAssessmentPresentation({
      score: null,
      scanQuality: quality,
      status: "completed",
      coverage: {
        reason: PHASE5_INCOMPLETE_REASON,
        incomplete_modules: customer.evidence.incomplete_modules,
      },
      }),
      ...(message ? { message } : {}),
    },
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

export const LEGACY_IDENTITY_REACHABILITY_REASON = "legacy_identity_reachability_semantics";

// Historical snapshots are immutable evidence. This pure read projection masks
// only conclusions that depended on the former provider/hostname-as-reachability
// semantics; unaffected facts and the input object remain untouched.
export function projectIdentitySnapshotForCustomer(snapshot, modules = {}) {
  if (!snapshot || typeof snapshot !== "object") return snapshot;
  const identityModule = modules?.identity_discovery;
  const domains = Array.isArray(snapshot.domains) ? snapshot.domains : [];
  const identityDomain = domains.find((entry) => entry?.domain_key === "identity_exposure");
  // The floor is passed EXPLICITLY. Relying on the default would compare against the
  // CURRENT resolver version, so every mint would silently re-classify honest history
  // as legacy and project a false "not evaluated by a supported producer" over it.
  const projectionAlreadyHonest = isResolverVersionAtLeast(
    snapshot?.methodology?.cyber_mot_resolver_version, FIRST_HONEST_RESOLVER_VERSION);
  const hasTypedReachability = Number.isFinite(Number(identityModule?.reachability_evaluated_count)) &&
    Number.isFinite(Number(identityModule?.reachable_surface_count));
  const legacyBriAffected = !projectionAlreadyHonest && !hasTypedReachability && Number(identityModule?.high_risk_count || 0) > 0;
  const legacyHealthyAffected = !projectionAlreadyHonest && identityDomain?.state === "assessed_healthy" && !hasTypedReachability;
  if (!legacyBriAffected && !legacyHealthyAffected) return { ...snapshot };

  const projectedDomains = domains.map((entry) => entry?.domain_key !== "identity_exposure" || !legacyHealthyAffected
    ? entry
    : {
        ...entry,
        state: "evidence_insufficient",
        coverage: "partial",
        state_reason: "Identity reachability was not evaluated by a supported producer; the historical healthy conclusion is withheld.",
        summary: "Identity reachability was not evaluated by a supported producer; the historical healthy conclusion is withheld.",
      });
  const overall = snapshot.overall ?? {};
  const bri = overall.business_risk_indicator ?? {};
  return {
    ...snapshot,
    domains: projectedDomains,
    overall: legacyBriAffected ? {
      ...overall,
      business_risk_indicator: {
        ...bri,
        band: null,
        explanation: null,
        provisional: true,
        withheld_reason: LEGACY_IDENTITY_REACHABILITY_REASON,
        internal_metrics: { ...(bri.internal_metrics ?? {}), score: null },
      },
    } : overall,
    customer_projection: {
      applied: true,
      reason: LEGACY_IDENTITY_REACHABILITY_REASON,
      identity_domain_withheld: legacyHealthyAffected,
      business_risk_indicator_withheld: legacyBriAffected,
    },
  };
}

/**
 * Customer renderer view of an immutable snapshot. The input object is never
 * mutated and remains available on read.snapshot for checksum/verbatim APIs.
 */
export const LEGACY_WEBSITE_REDIRECT_REASON = "legacy_non_serviceable_redirect_conclusion";
export const LEGACY_WEBSITE_REDIRECT_FINDING = "ssl_no_http_redirect";

/**
 * projectWebsiteRedirectSnapshotForCustomer(snapshot, modules)
 *
 * Read-time customer view; immutable snapshot bytes and checksum remain untouched.
 *
 * THE CLASS. Before P1.1, `ssl-scan.js` set `http_redirect_validated` from TRANSPORT
 * observation, so an origin that answered 5xx on the plain-HTTP hop — never serving,
 * never revealing whether it redirects — nonetheless "validated" the redirect
 * decision and published a scored `ssl_no_http_redirect` defect. Those conclusions
 * are frozen into stored snapshots and are still read at face value.
 *
 * THE DISCRIMINATOR IS THE EVIDENCE SHAPE, NOT A VERSION. A version gate would be a
 * moving boundary, and #424 proved what that costs: comparing stored rows against a
 * constant that moves on every mint re-classifies honest history as legacy. The
 * recorded chain says outright whether the hop that "validated" the redirect was
 * serviceable, so this projection asks the evidence, not the calendar. Snapshots
 * minted after the producer was corrected cannot exhibit the shape at all.
 *
 * FAIL NEUTRAL, NOT FAIL-MASKING. When the source modules are unavailable — the
 * explicit `{}` fallback report-snapshot.js uses when the R2 source read fails — the
 * shape CANNOT be evaluated. The snapshot is then returned untouched. Masking on
 * absent evidence is the same error in the opposite direction: it would tell a
 * customer their honest historical conclusion was unfounded, on no evidence at all.
 */
export function projectWebsiteRedirectSnapshotForCustomer(snapshot, modules = {}) {
  if (!snapshot || typeof snapshot !== "object") return snapshot;
  const chain = modules?.ssl?.http_redirect_chain;
  // No readable chain => cannot evaluate => say nothing.
  if (!chain || typeof chain !== "object") return snapshot;
  if (chain.http_redirect_validated !== true) return snapshot;

  // The hop whose answer was treated as the redirect decision.
  const hops = Array.isArray(chain.hop_observations) ? chain.hop_observations : [];
  const firstHop = hops.length ? hops[0] : null;
  const observation = firstHop
    ? { state: firstHop.state ?? chain.observation_state, origin_status: firstHop.origin_status }
    : { state: chain.observation_state, origin_status: chain.origin_status };
  if (typeof observation.state !== "string") return snapshot;   // unreadable => neutral
  const serviceability = classifyServiceability(observation);
  // Serviceable evidence: the historical conclusion stands. Unknown also stands —
  // only a POSITIVE reading of "this could not have grounded a defect" projects.
  if (serviceability.serviceable !== false) return snapshot;
  if (maySupportDefectConclusion(serviceability)) return snapshot;

  const findings = Array.isArray(snapshot.observed_findings) ? snapshot.observed_findings : [];
  const kept = findings.filter((f) => f?.finding_id !== LEGACY_WEBSITE_REDIRECT_FINDING);
  if (kept.length === findings.length) return snapshot;         // the class is not present here

  const withheld = "The recorded HTTP hop did not serve a response, so whether this site "
    + "redirected to HTTPS was never observed; the historical defect conclusion is withheld.";
  const domains = (Array.isArray(snapshot.domains) ? snapshot.domains : []).map((entry) => {
    if (entry?.domain_key !== "website_security") return entry;
    const ids = (Array.isArray(entry.finding_ids) ? entry.finding_ids : [])
      .filter((id) => id !== LEGACY_WEBSITE_REDIRECT_FINDING);
    return {
      ...entry,
      state: "evidence_insufficient",
      coverage: "partial",
      state_reason: withheld,
      summary: withheld,
      finding_ids: ids,
      finding_count: ids.length,
    };
  });
  const overall = snapshot.overall ?? {};
  return {
    ...snapshot,
    domains,
    observed_findings: kept,
    overall: { ...overall, cyber_metrics_score: null, score_band: null },
    customer_projection: {
      ...(snapshot.customer_projection ?? {}),
      applied: true,
      website_redirect_withheld: true,
      website_redirect_reason: LEGACY_WEBSITE_REDIRECT_REASON,
    },
  };
}

export function projectPhase5SnapshotForCustomer(snapshot, modules = {}) {
  const tlsSnapshot = projectTlsSnapshotForCustomer(snapshot, modules);
  const identitySnapshot = projectIdentitySnapshotForCustomer(tlsSnapshot, modules);
  const websiteSnapshot = projectWebsiteRedirectSnapshotForCustomer(identitySnapshot, modules);
  const overall = websiteSnapshot?.overall ?? {};
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
  if (projection.evidence.complete) return websiteSnapshot;

  const bri = overall.business_risk_indicator ?? {};
  return {
    ...websiteSnapshot,
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
  if (!env?.cybermeters_reports || !scanId) {
    return {
      state: "unavailable",
      reason: "evidence_store_unavailable",
      modules: {},
    };
  }
  try {
    const object = await env.cybermeters_reports.get(`reports/${scanId}.json`);
    if (!object) {
      return {
        state: "unavailable",
        reason: "stored_report_missing",
        modules: {},
      };
    }
    const report = object ? await object.json() : null;
    if (!report?.modules || typeof report.modules !== "object") {
      return {
        state: "unavailable",
        reason: "stored_module_contract_missing",
        modules: {},
      };
    }
    return {
      state: "verified",
      reason: null,
      modules: report.modules,
      // The report snapshot and Executive PDF feed this identical frozen
      // monitoring contract into resolveAssessmentPresentation. Carry it
      // through the bounded read adapter so list rows reuse the same decision.
      monitoring_states: report.monitoring_states ?? null,
    };
  } catch {
    return {
      state: "unavailable",
      reason: "stored_report_read_failed",
      modules: {},
    };
  }
}

async function boundedMap(items, concurrency, mapper) {
  const results = new Array(items.length);
  let cursor = 0;
  const workerCount = Math.min(concurrency, items.length);
  await Promise.all(Array.from({ length: workerCount }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await mapper(items[index], index);
    }
  }));
  return results;
}

function attachEvidenceReadCoverage(rows, coverage) {
  Object.defineProperty(rows, "phase5_evidence_coverage", {
    value: Object.freeze(coverage),
    enumerable: false,
    configurable: false,
    writable: false,
  });
  return rows;
}

export function phase5EvidenceReadCoverage(rows) {
  if (rows?.phase5_evidence_coverage) return rows.phase5_evidence_coverage;
  const values = Array.isArray(rows) ? rows : [];
  const completed = values.filter((row) => row?.status === "completed");
  const missingScanIdRows = completed.filter(
    (row) => !(row.id ?? row.scan_id),
  );
  const uniqueOutcomes = new Map();
  for (const row of completed) {
    const scanId = row.id ?? row.scan_id;
    if (scanId) {
      uniqueOutcomes.set(scanId, row?.phase5_evidence_read?.state);
    }
  }
  const readStates = completed.map((row) => row?.phase5_evidence_read?.state);
  if (completed.length > 0 && readStates.every(Boolean)) {
    const uniqueStates = [...uniqueOutcomes.values()];
    const boundedOut = uniqueStates.filter(
      (state) => state === "bounded_out",
    ).length;
    const verified = uniqueStates.filter(
      (state) => state === "verified",
    ).length;
    const unavailable =
      uniqueStates.length - verified - boundedOut;
    const complete =
      readStates.every((state) => state === "verified") &&
      missingScanIdRows.length === 0;
    return {
      contract: PHASE5_EVIDENCE_READ_CONTRACT,
      state: complete ? "complete" : "partial",
      complete,
      truncated: boundedOut > 0,
      reason: complete
        ? null
        : boundedOut > 0
          ? "evidence_read_bound_exceeded"
          : "stored_report_evidence_unavailable",
      row_count: values.length,
      completed_row_count: completed.length,
      unique_scan_count: uniqueOutcomes.size,
      reads_attempted: verified + unavailable,
      reads_verified: verified,
      reads_unavailable: unavailable,
      bounded_out_scan_count: boundedOut,
      missing_scan_id_row_count: missingScanIdRows.length,
      concurrency_limit: PHASE5_EVIDENCE_READ_CONCURRENCY,
      read_limit: PHASE5_EVIDENCE_READ_LIMIT,
    };
  }
  return {
    contract: PHASE5_EVIDENCE_READ_CONTRACT,
    state: "unavailable",
    complete: false,
    truncated: false,
    reason: "projection_coverage_missing",
    row_count: Array.isArray(rows) ? rows.length : 0,
    completed_row_count: 0,
    unique_scan_count: 0,
    reads_attempted: 0,
    reads_verified: 0,
    reads_unavailable: 0,
    bounded_out_scan_count: 0,
    missing_scan_id_row_count: 0,
    concurrency_limit: PHASE5_EVIDENCE_READ_CONCURRENCY,
    read_limit: PHASE5_EVIDENCE_READ_LIMIT,
  };
}

/**
 * An aggregate excludes incomplete assessments and states its denominator.
 * A null score is never converted to zero, and the evidence coverage always
 * makes the assessed/eligible population explicit.
 */
export function resolvePhase5CustomerAggregate(rows = []) {
  const coverage = phase5EvidenceReadCoverage(rows);
  const candidates = (rows ?? []).filter((row) => row?.status === "completed");
  const incompleteRows = candidates.filter((row) =>
    row?.phase5_evidence_read?.state !== "verified" ||
    row?.phase5_evidence?.complete !== true ||
    !Number.isFinite(row?.score)
  );
  const assessedRows = candidates.filter((row) =>
    row?.phase5_evidence_read?.state === "verified" &&
    row?.phase5_evidence?.complete === true &&
    Number.isFinite(row?.score)
  );
  const complete = coverage.complete === true && incompleteRows.length === 0;
  const scores = assessedRows.map((row) => row.score);
  return {
    complete,
    score: scores.length
      ? scores.reduce((sum, score) => sum + score, 0) / scores.length
      : null,
    rating: null,
    scores,
    evidence_coverage: {
      ...coverage,
      assessment_complete: complete,
      assessed_row_count: assessedRows.length,
      incomplete_row_count: incompleteRows.length,
      reason: complete
        ? null
        : coverage.reason ?? "phase5_assessment_incomplete",
    },
  };
}

/**
 * Bounded read-time adapter for D1 scan rows. It performs no writes and removes
 * score/rating unless the referenced immutable report explicitly proves every
 * required Phase-5 module publishable.
 */
export async function projectPhase5ScanRowsForCustomer(env, rows = []) {
  const inputRows = Array.isArray(rows) ? rows : [];
  const completedRows = inputRows.filter((row) => row?.status === "completed");
  const missingScanIdRowCount = completedRows.filter(
    (row) => !(row.id ?? row.scan_id),
  ).length;
  const uniqueScanIds = [];
  const seenScanIds = new Set();
  for (const row of completedRows) {
    const scanId = row.id ?? row.scan_id;
    if (scanId && !seenScanIds.has(scanId)) {
      seenScanIds.add(scanId);
      uniqueScanIds.push(scanId);
    }
  }

  const readableScanIds = uniqueScanIds.slice(0, PHASE5_EVIDENCE_READ_LIMIT);
  const boundedOutScanIds = new Set(
    uniqueScanIds.slice(PHASE5_EVIDENCE_READ_LIMIT),
  );
  const outcomes = await boundedMap(
    readableScanIds,
    PHASE5_EVIDENCE_READ_CONCURRENCY,
    async (scanId) => [scanId, await readStoredPhase5Modules(env, scanId)],
  );
  const outcomeByScanId = new Map(outcomes);

  const projected = inputRows.map((row) => {
    if (!row || row.status !== "completed") return row;
    const scanId = row.id ?? row.scan_id;
    const outcome = !scanId
      ? {
          state: "unavailable",
          reason: "scan_id_missing",
          modules: {},
        }
      : boundedOutScanIds.has(scanId)
        ? {
            state: "bounded_out",
            reason: "evidence_read_bound_exceeded",
            modules: {},
          }
        : outcomeByScanId.get(scanId) ?? {
            state: "unavailable",
            reason: "evidence_read_not_attempted",
            modules: {},
          };
    const customer = resolvePhase5HistoricalCustomerProjection({
      score: row.score,
      riskLevel: row.rating,
      scanQuality: row.scan_quality,
      modules: outcome.modules,
      monitoringStates: outcome.monitoring_states,
    });
    return {
      ...row,
      score: customer.score,
      rating: customer.risk_level,
      scan_quality: customer.scan_quality,
      assessment: customer.assessment,
      phase5_evidence: {
        ...customer.evidence,
        evidence_read_state: outcome.state,
        evidence_read_reason: outcome.reason,
      },
      phase5_evidence_read: {
        contract: PHASE5_EVIDENCE_READ_CONTRACT,
        state: outcome.state,
        reason: outcome.reason,
        verified: outcome.state === "verified",
      },
    };
  });

  const readsVerified = outcomes.filter(([, value]) =>
    value.state === "verified"
  ).length;
  const readsUnavailable = outcomes.length - readsVerified;
  const boundedOutScanCount = boundedOutScanIds.size;
  const complete =
    boundedOutScanCount === 0 &&
    readsUnavailable === 0 &&
    missingScanIdRowCount === 0;
  return attachEvidenceReadCoverage(projected, {
    contract: PHASE5_EVIDENCE_READ_CONTRACT,
    state: complete ? "complete" : "partial",
    complete,
    truncated: boundedOutScanCount > 0,
    reason:
      boundedOutScanCount > 0
        ? "evidence_read_bound_exceeded"
        : readsUnavailable > 0
          ? "stored_report_evidence_unavailable"
          : missingScanIdRowCount > 0
            ? "scan_id_missing"
            : null,
    row_count: inputRows.length,
    completed_row_count: completedRows.length,
    unique_scan_count: uniqueScanIds.length,
    reads_attempted: outcomes.length,
    reads_verified: readsVerified,
    reads_unavailable: readsUnavailable,
    bounded_out_scan_count: boundedOutScanCount,
    missing_scan_id_row_count: missingScanIdRowCount,
    concurrency_limit: PHASE5_EVIDENCE_READ_CONCURRENCY,
    read_limit: PHASE5_EVIDENCE_READ_LIMIT,
  });
}
