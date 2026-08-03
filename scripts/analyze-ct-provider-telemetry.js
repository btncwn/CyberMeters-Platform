#!/usr/bin/env node
// CT-R1 read-only rolling seven-day analysis.
//
// Input is the JSON result of READ_QUERY (a raw result array or Wrangler --json
// envelope). No database write is issued by this script.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const CT_TELEMETRY_MEASUREMENT_STATES = Object.freeze([
  "not_measured",
  "partial_coverage",
  "measured",
]);

const CT_PROVIDERS = Object.freeze(["crt_sh", "certspotter"]);

export const READ_QUERY = `
SELECT
  s.id AS scan_id,
  s.workspace_id,
  s.scan_quality,
  s.created_at AS scan_created_at,
  t.module,
  t.provider,
  t.outcome,
  t.http_status,
  t.latency_ms,
  t.result_count,
  t.started_at,
  t.completed_at,
  t.completeness_impact,
  t.affected_signal,
  t.cache_state,
  t.cache_age_s,
  o.source_set_version
FROM scans AS s
LEFT JOIN ct_provider_telemetry AS t ON t.scan_id = s.id
LEFT JOIN ct_provider_overlap_telemetry AS o
  ON o.scan_id = s.id AND o.module = 'subdomains'
WHERE s.created_at >= datetime('now', '-7 days')
ORDER BY s.created_at, s.id, t.started_at, t.provider, t.module
`.trim();

function percentile(values, quantile) {
  if (values.length === 0) return null;
  const ordered = [...values].sort((a, b) => a - b);
  const index = Math.max(0, Math.ceil(quantile * ordered.length) - 1);
  return ordered[index];
}

function physicalAttemptKey(row) {
  return [
    row.scan_id,
    row.provider,
    row.started_at,
    row.completed_at,
    row.outcome,
    row.http_status,
    row.latency_ms,
    row.result_count,
  ].join("\u0000");
}

export function analyzeCtProviderTelemetry(rows, {
  nowMs = Date.now(),
  windowDays = 7,
  founderWorkspaceIds = [],
} = {}) {
  const windowStartMs = nowMs - windowDays * 86_400_000;
  const inWindow = rows.filter((row) => {
    const createdMs = Date.parse(row.scan_created_at);
    return Number.isFinite(createdMs) &&
      createdMs >= windowStartMs &&
      createdMs <= nowMs;
  });

  const scans = new Map();
  for (const row of inWindow) {
    if (!scans.has(row.scan_id)) scans.set(row.scan_id, row.scan_quality ?? null);
  }
  const completed = [...scans.values()].filter((quality) => quality === "complete").length;
  const completionLoss = scans.size - completed;

  // Count the attempt population before any completeness-impact filter. A
  // platform deadline is a CyberMeters cause whether or not it changed the
  // final scan-quality band.
  const attemptRows = rows.filter((row) => row.provider && row.outcome);
  // Date an attempt by its scan, falling back to the attempt's own start. A row
  // that silently dropped out of the cohort could not quarantine it, so an
  // undatable v1 row would leave a cohort reading "eligible" while unquarantined
  // v1 evidence sat inside it. Undated rows are counted and fail closed instead.
  const attemptRowTimeMs = (row) => {
    const createdMs = Date.parse(row.scan_created_at);
    if (Number.isFinite(createdMs)) return createdMs;
    const startedMs = Date.parse(row.started_at);
    return Number.isFinite(startedMs) ? startedMs : null;
  };
  const datedAttemptRows = attemptRows.filter((row) => attemptRowTimeMs(row) !== null);
  const undatedAttemptRows = attemptRows.length - datedAttemptRows.length;
  const inWindowAttemptRows = datedAttemptRows.filter((row) => {
    const createdMs = attemptRowTimeMs(row);
    return createdMs >= windowStartMs && createdMs <= nowMs;
  });

  // Rows are duplicated only when one physical attempt fed both module consumers.
  const physicalAttempts = new Map();
  for (const row of inWindowAttemptRows) {
    const key = physicalAttemptKey(row);
    if (!physicalAttempts.has(key)) physicalAttempts.set(key, row);
  }
  const scansWithTelemetry = new Set(
    [...physicalAttempts.values()].map((row) => row.scan_id)
  );
  const scansWithoutTelemetry = scans.size - scansWithTelemetry.size;
  const telemetryMeasurementState = scans.size === 0 || scansWithTelemetry.size === 0
    ? "not_measured"
    : scansWithTelemetry.size < scans.size
      ? "partial_coverage"
      : "measured";
  const telemetryCoveragePct = scans.size === 0
    ? null
    : Number(((scansWithTelemetry.size / scans.size) * 100).toFixed(2));

  const attributionSets = new Map();
  const attributedCompletionLossScans = new Set();
  for (const row of inWindow) {
    if (!row.provider || row.outcome === "ok" || Number(row.completeness_impact) !== 1) {
      continue;
    }
    const key = `${row.provider}\u0000${row.outcome}`;
    if (!attributionSets.has(key)) attributionSets.set(key, new Set());
    attributionSets.get(key).add(row.scan_id);
    if (scans.get(row.scan_id) !== "complete") {
      attributedCompletionLossScans.add(row.scan_id);
    }
  }
  const completionLossAttributed = attributedCompletionLossScans.size;
  const completionLossUnattributed = Math.max(0, completionLoss - completionLossAttributed);
  const failureAttribution = [...attributionSets.entries()]
    .map(([key, scanIds]) => {
      const [provider, error_class] = key.split("\u0000");
      return {
        provider,
        error_class,
        completion_loss_scans: scanIds.size,
        pct_of_completion_loss: completionLoss === 0
          ? null
          : Number(((scanIds.size / completionLoss) * 100).toFixed(2)),
      };
    })
    .sort((a, b) =>
      a.provider.localeCompare(b.provider) ||
      a.error_class.localeCompare(b.error_class)
    );

  const latencyByProvider = new Map();
  for (const row of physicalAttempts.values()) {
    const latency = Number(row.latency_ms);
    if (!Number.isFinite(latency)) continue;
    if (!latencyByProvider.has(row.provider)) latencyByProvider.set(row.provider, []);
    latencyByProvider.get(row.provider).push(latency);
  }
  const latencyPercentiles = CT_PROVIDERS
    .map((provider) => {
      const values = latencyByProvider.get(provider) || [];
      const measurementState = values.length === 0
        ? "not_measured"
        : telemetryMeasurementState === "partial_coverage"
          ? "partial_coverage"
          : "measured";
      return {
        provider,
        attempts: values.length,
        measurement_state: measurementState,
        message: values.length === 0
          ? "No latency samples were measured for this provider."
          : measurementState === "partial_coverage"
            ? "Percentiles use the available samples; CT telemetry coverage is partial."
            : "Percentiles use all measured CT attempts in the window.",
        p50_ms: percentile(values, 0.50),
        p90_ms: percentile(values, 0.90),
        p99_ms: percentile(values, 0.99),
      };
    })
    .sort((a, b) => a.provider.localeCompare(b.provider));

  const providerOutcomesByScan = new Map();
  for (const row of physicalAttempts.values()) {
    if (!providerOutcomesByScan.has(row.scan_id)) {
      providerOutcomesByScan.set(row.scan_id, new Map());
    }
    const providerMap = providerOutcomesByScan.get(row.scan_id);
    if (!providerMap.has(row.provider)) providerMap.set(row.provider, []);
    providerMap.get(row.provider).push(row.outcome);
  }
  let bothAttempted = 0;
  let bothFailed = 0;
  for (const providerMap of providerOutcomesByScan.values()) {
    if (!providerMap.has("crt_sh") || !providerMap.has("certspotter")) continue;
    bothAttempted += 1;
    const crtFailed = !providerMap.get("crt_sh").includes("ok");
    const certspotterFailed = !providerMap.get("certspotter").includes("ok");
    if (crtFailed && certspotterFailed) bothFailed += 1;
  }

  const telemetryCoverageMessage = telemetryMeasurementState === "not_measured"
    ? scans.size === 0
      ? "No scans exist in the analysis window; CT telemetry coverage is not measured."
      : "Scans exist, but none has CT provider telemetry."
    : telemetryMeasurementState === "partial_coverage"
      ? "CT provider telemetry exists for only part of the scan population."
      : "CT provider telemetry covers every scan in the analysis window.";
  const coFailureMeasurementState = bothAttempted === 0
    ? "not_measured"
    : telemetryMeasurementState;

  const sourceSetVersions = [...new Set(inWindowAttemptRows
    .map((row) => row.source_set_version)
    .filter(Boolean))].sort();
  const allRowsAreV2 = inWindowAttemptRows.length > 0
    && undatedAttemptRows === 0
    && inWindowAttemptRows.every((row) => row.source_set_version === "ct-provider-overlap/2");
  const decisionRows = allRowsAreV2 ? inWindowAttemptRows : [];
  const scopeSummary = (scopeRows) => {
    const groups = new Map();
    for (const row of scopeRows) {
      const key = `${row.module || "unknown"}\u0000${row.provider || "unknown"}`;
      if (!groups.has(key)) {
        groups.set(key, {
          module: row.module || null,
          provider: row.provider || null,
          total_attempt_rows: 0,
          platform_deadline_abort_attempt_rows: 0,
          completeness_impacting_platform_deadline_abort_attempt_rows: 0,
        });
      }
      const group = groups.get(key);
      group.total_attempt_rows += 1;
      if (row.outcome === "platform_deadline_abort") {
        group.platform_deadline_abort_attempt_rows += 1;
        if (Number(row.completeness_impact) === 1) {
          group.completeness_impacting_platform_deadline_abort_attempt_rows += 1;
        }
      }
    }
    const platformRows = scopeRows.filter((row) => row.outcome === "platform_deadline_abort");
    return {
      total_attempt_rows: scopeRows.length,
      platform_deadline_abort_attempt_rows: platformRows.length,
      completeness_impacting_platform_deadline_abort_attempt_rows:
        platformRows.filter((row) => Number(row.completeness_impact) === 1).length,
      by_module_provider: [...groups.values()].sort((a, b) =>
        String(a.module).localeCompare(String(b.module))
        || String(a.provider).localeCompare(String(b.provider))),
    };
  };
  const founderSet = new Set(founderWorkspaceIds.map(String));
  const founderRows = inWindowAttemptRows.filter((row) => founderSet.has(String(row.workspace_id)));

  return {
    window_days: windowDays,
    window_start: new Date(windowStartMs).toISOString(),
    window_end: new Date(nowMs).toISOString(),
    completion: {
      scans: scans.size,
      scans_total: scans.size,
      complete: completed,
      completion_loss: completionLoss,
      telemetry_measurement_state: telemetryMeasurementState,
      telemetry_coverage_pct: telemetryCoveragePct,
      completion_rate_pct: scans.size === 0
        ? null
        : Number(((completed / scans.size) * 100).toFixed(2)),
      message: scans.size === 0
        ? "Completion rate is not measured because no scans exist in the window."
        : telemetryMeasurementState === "measured"
          ? "Completion rate is shown with full CT telemetry coverage."
          : `Completion rate is measured from scans, but provider attribution is ${telemetryMeasurementState}.`,
    },
    telemetry_coverage: {
      measurement_state: telemetryMeasurementState,
      message: telemetryCoverageMessage,
      scans_total: scans.size,
      scans_with_ct_telemetry: scansWithTelemetry.size,
      scans_without_ct_telemetry: scansWithoutTelemetry,
      telemetry_coverage_pct: telemetryCoveragePct,
      completion_loss_total: completionLoss,
      completion_loss_attributed: completionLossAttributed,
      completion_loss_unattributed: completionLossUnattributed,
    },
    failure_attribution: {
      measurement_state: telemetryMeasurementState,
      message: telemetryMeasurementState === "not_measured"
        ? "Provider failure attribution is not measured because no CT telemetry rows exist."
        : telemetryMeasurementState === "partial_coverage"
          ? "Provider failure attribution uses available rows; uncovered completion loss remains unattributed."
          : "Provider failure attribution uses full CT telemetry coverage.",
      rows: failureAttribution,
    },
    latency_percentiles: latencyPercentiles,
    co_failure: {
      measurement_state: coFailureMeasurementState,
      message: bothAttempted === 0
        ? "Co-failure is not measured because no scan attempted both providers."
        : coFailureMeasurementState === "partial_coverage"
          ? "Co-failure uses scans where both providers were measured; overall CT telemetry coverage is partial."
          : "Co-failure uses all scans where both providers were measured.",
      scans_with_both_providers_attempted: bothAttempted,
      both_providers_failed: bothFailed,
      co_failure_rate_pct: bothAttempted === 0
        ? null
        : Number(((bothFailed / bothAttempted) * 100).toFixed(2)),
    },
    decision_grade: {
      required_source_set_version: "ct-provider-overlap/2",
      status: inWindowAttemptRows.length === 0
        ? "not_measured"
        : allRowsAreV2
          ? "eligible"
          : sourceSetVersions.includes("ct-provider-overlap/2")
            ? "mixed_cohort_rejected"
            : "historical_cohort_quarantined",
      source_set_versions: sourceSetVersions,
      included_rows: decisionRows.length,
      excluded_rows: inWindowAttemptRows.length - decisionRows.length,
      undated_attempt_rows: undatedAttemptRows,
    },
    platform_deadline_censorship: {
      measurement_state: decisionRows.length > 0 ? "measured" : "not_measured",
      required_source_set_version: "ct-provider-overlap/2",
      scopes: {
        global: scopeSummary(decisionRows),
        founder: scopeSummary(decisionRows.filter((row) =>
          founderSet.has(String(row.workspace_id)))),
        founder_observed_unfiltered: scopeSummary(founderRows),
      },
    },
  };
}

function parseWranglerJson(value) {
  if (Array.isArray(value) && value.length > 0 && Array.isArray(value[0]?.results)) {
    return value.flatMap((entry) => entry.results || []);
  }
  if (Array.isArray(value?.results)) return value.results;
  if (Array.isArray(value)) return value;
  throw new Error("Expected a JSON result array or Wrangler --json result envelope");
}

function argumentValue(flag) {
  const index = process.argv.indexOf(flag);
  return index >= 0 ? process.argv[index + 1] : null;
}

const isMain = process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  if (process.argv.includes("--print-sql")) {
    process.stdout.write(`${READ_QUERY}\n`);
  } else {
    const inputPath = argumentValue("--input");
    const nowArg = argumentValue("--now");
    const nowMs = nowArg == null ? Date.now() : Date.parse(nowArg);
    if (!Number.isFinite(nowMs)) throw new Error("--now must be an ISO timestamp");
    const input = inputPath
      ? fs.readFileSync(inputPath, "utf8")
      : fs.readFileSync(0, "utf8");
    const rows = parseWranglerJson(JSON.parse(input));
    process.stdout.write(`${JSON.stringify(
      analyzeCtProviderTelemetry(rows, { nowMs }),
      null,
      2
    )}\n`);
  }
}
