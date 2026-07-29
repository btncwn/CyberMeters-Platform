// ── Canonical assessment presentation resolver ────────────────────────────────
// The SINGLE seam that turns a raw score + scan coverage quality into a customer-
// facing decision. Raw scoring (computeScore / riskLevelForScore) stays PURE — this
// module owns all provisional / authoritative / comparable / rating / message
// semantics. Every score/rating surface (dashboard, scan detail, executive report,
// PDF, scorecard, insights, portfolio, API, trends) MUST delegate here so they can
// never disagree about whether a result is a final clean conclusion.
//
// Strict trust model (partial-scan honesty): ONLY quality='complete' is
// authoritative, comparable, and may show a final rating. partial / degraded /
// unknown are provisional — a raw score may be shown as provisional, but never an
// unqualified rating, and they never establish/replace the authoritative posture or
// participate in trend deltas. NULL/legacy quality = 'unknown', NEVER 'complete'.

import { riskLevelForScore } from "./scoring.js";
import {
  SIGNAL_MONITORING_DEFINITIONS,
  resolveSignalMonitoringCoverage,
} from "./signal-monitoring-state.js";

export const SCAN_QUALITY = Object.freeze({
  COMPLETE: "complete", PARTIAL: "partial", DEGRADED: "degraded", UNKNOWN: "unknown",
});

// NULL / undefined / any unrecognised value → 'unknown' (never 'complete'). Quality
// describes EXECUTION + EVIDENCE COVERAGE, not security posture — a clean scan with
// no findings is still 'complete'; a scan whose risk-producing checks did not run is
// 'partial'; degraded evidence sources are 'degraded'.
export function normalizeQuality(q) {
  const v = String(q ?? "").trim().toLowerCase();
  return (v === "complete" || v === "partial" || v === "degraded") ? v : "unknown";
}

// Customer-safe status messages (status language only — no product copy).
export const ASSESSMENT_MESSAGES = Object.freeze({
  complete: null,
  partial:  "Some checks were not completed. This score is provisional.",
  degraded: "Some checks or evidence sources were degraded. This score is provisional.",
  unknown:  "Legacy assessment — coverage quality unavailable.",
});

// Scan-completion delivery needs a self-contained caveat because some channels
// (asset alerts and first-scan lifecycle email) do not render a score. These are
// presentation strings over the existing quality enum, not a new customer-state
// model. Only an explicit complete quality may omit the caveat.
export const SCAN_COMPLETION_DISCLOSURES = Object.freeze({
  complete: null,
  partial:  "Partial scan — some checks did not complete this run; results may be incomplete.",
  degraded: "Degraded scan — some checks or evidence sources did not complete normally; results may be incomplete.",
  unknown:  "Scan coverage was not confirmed for this run; results may be incomplete.",
});

export function scanCompletionQualityDisclosure(scanQuality) {
  const quality = normalizeQuality(scanQuality);
  const complete = quality === SCAN_QUALITY.COMPLETE;
  return {
    quality,
    complete,
    disclosure: complete ? null : SCAN_COMPLETION_DISCLOSURES[quality],
  };
}

// Converts the already-resolved backend signal states into completion copy. This
// function does not derive a verdict: it only presents the canonical state/message
// pairs. Unknown states fail closed as non-healthy. "Other checks completed
// normally" is safe only when scan_quality is complete and exactly one signal is
// non-healthy; otherwise every attributable limitation is stated without it.
export function signalMonitoringDisclosure(monitoringStates, { otherChecksCompleted = false } = {}) {
  const entries = Object.values(monitoringStates?.signals ?? {});
  const nonHealthy = entries.filter((entry) =>
    entry?.state !== "monitoring_healthy"
  );
  if (nonHealthy.length === 0) return null;

  const messages = [...new Set(nonHealthy.map((entry) =>
    String(entry?.message || "Monitoring evidence was incomplete in this run.").trim()
  ).filter(Boolean))];
  if (messages.length === 0) return "Monitoring evidence was incomplete in this run.";

  const disclosure = messages.join(" ");
  return otherChecksCompleted && nonHealthy.length === 1
    ? `${disclosure} Other checks completed normally.`
    : disclosure;
}

export function buildScanCompletionPresentation({
  domain,
  score,
  riskLevel,
  scanQuality,
  monitoringStates = null,
} = {}) {
  const rawQuality = scanCompletionQualityDisclosure(scanQuality);
  const monitoringCoverage = monitoringStates
    ? resolveSignalMonitoringCoverage(
        monitoringStates,
        Object.keys(SIGNAL_MONITORING_DEFINITIONS)
      )
    : null;
  // A scan may finish all core execution without collecting every decisive
  // provider-backed signal. Keep the execution success, but coverage-cap the
  // customer-facing score/risk conclusion.
  const effectiveQuality =
    rawQuality.complete && monitoringCoverage && !monitoringCoverage.complete
      ? SCAN_QUALITY.DEGRADED
      : rawQuality.quality;
  const quality = scanCompletionQualityDisclosure(effectiveQuality);
  const signalDisclosure = signalMonitoringDisclosure(monitoringStates, {
    otherChecksCompleted: rawQuality.complete,
  });
  const hasScore = Number.isFinite(score);
  if (quality.complete) {
    if (signalDisclosure) {
      return {
        ...quality,
        disclosure: signalDisclosure,
        description: hasScore
          ? `Scan completed for ${domain} — score ${score}, risk ${riskLevel}. ${signalDisclosure}`
          : `Scan completed for ${domain}. ${signalDisclosure}`,
        message: hasScore
          ? `Score: ${score} · ${riskLevel} risk · ${signalDisclosure}`
          : signalDisclosure,
      };
    }
    return {
      ...quality,
      description: hasScore
        ? `Scan completed for ${domain} — score ${score}, risk ${riskLevel}`
        : `Scan completed for ${domain}`,
      message: hasScore ? `Score: ${score} · ${riskLevel} risk` : "Scan completed.",
    };
  }
  const disclosure = signalDisclosure || quality.disclosure;
  return {
    ...quality,
    disclosure,
    description: hasScore
      ? `Scan completed for ${domain} — score ${score} (provisional). ${disclosure}`
      : `Scan completed for ${domain}. ${disclosure}`,
    message: hasScore ? `Score: ${score} (provisional) · ${disclosure}` : disclosure,
  };
}

// Shown when a scope has NO complete assessment to establish authoritative posture.
export const POSTURE_NOT_ESTABLISHED_MESSAGE = "Current posture not yet established.";

// The canonical decision model. `scanQuality` is the persisted scans.scan_quality
// (or report.scan_quality.status). `status` is the D1 scan status; a non-completed
// scan yields no usable score. `coverage` is optional detail (e.g. modules_skipped)
// passed through untouched for callers that want to render specifics.
export function resolveAssessmentPresentation({
  score = null,
  scanQuality = null,
  status = null,
  coverage = null,
  monitoringStates = undefined,
  requireMonitoring = false,
} = {}) {
  const rawQuality = normalizeQuality(scanQuality);
  const monitoringEvaluated = requireMonitoring || monitoringStates !== undefined;
  const monitoringCoverage = monitoringEvaluated
    ? resolveSignalMonitoringCoverage(
        monitoringStates,
        Object.keys(SIGNAL_MONITORING_DEFINITIONS)
      )
    : null;
  const quality =
    rawQuality === SCAN_QUALITY.COMPLETE &&
    monitoringCoverage &&
    !monitoringCoverage.complete
      ? SCAN_QUALITY.DEGRADED
      : rawQuality;
  const complete = quality === "complete";
  // A score is only usable when the scan actually completed.
  const completed = status == null || String(status).toLowerCase() === "completed";
  const hasScore  = completed && Number.isFinite(score);

  return {
    raw_score:      hasScore ? score : null,
    // The raw number may be shown for provisional results, but it is NOT a rating.
    display_score:  hasScore ? score : null,
    // A final rating is displayed ONLY for a complete assessment.
    display_rating: complete && hasScore ? riskLevelForScore(score) : null,
    quality,
    provisional:    !complete,
    authoritative:  complete,
    comparable:     complete,
    coverage: monitoringEvaluated
      ? {
          ...(coverage ?? {}),
          raw_scan_quality: rawQuality,
          monitoring_state: monitoringCoverage.state,
          monitoring_signals: monitoringCoverage.signals,
        }
      : (coverage ?? null),
    message:        hasScore
      ? ASSESSMENT_MESSAGES[quality]
      : (complete ? null : SCAN_COMPLETION_DISCLOSURES[quality]),
  };
}
