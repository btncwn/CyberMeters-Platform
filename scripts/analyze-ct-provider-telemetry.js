#!/usr/bin/env node
// CT-R1 read-only rolling seven-day analysis.
//
// Input is the JSON result of READ_QUERY (a raw result array or Wrangler --json
// envelope). No database write is issued by this script.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const READ_QUERY = `
SELECT
  s.id AS scan_id,
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
  t.cache_age_s
FROM scans AS s
LEFT JOIN ct_provider_telemetry AS t ON t.scan_id = s.id
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

  // Rows are duplicated only when one physical attempt fed both module consumers.
  const physicalAttempts = new Map();
  for (const row of inWindow) {
    if (!row.provider || !row.outcome) continue;
    const key = physicalAttemptKey(row);
    if (!physicalAttempts.has(key)) physicalAttempts.set(key, row);
  }

  const attributionSets = new Map();
  for (const row of inWindow) {
    if (!row.provider || row.outcome === "ok" || Number(row.completeness_impact) !== 1) {
      continue;
    }
    const key = `${row.provider}\u0000${row.outcome}`;
    if (!attributionSets.has(key)) attributionSets.set(key, new Set());
    attributionSets.get(key).add(row.scan_id);
  }
  const failureAttribution = [...attributionSets.entries()]
    .map(([key, scanIds]) => {
      const [provider, error_class] = key.split("\u0000");
      return {
        provider,
        error_class,
        completion_loss_scans: scanIds.size,
        pct_of_completion_loss: completionLoss === 0
          ? 0
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
  const latencyPercentiles = [...latencyByProvider.entries()]
    .map(([provider, values]) => ({
      provider,
      attempts: values.length,
      p50_ms: percentile(values, 0.50),
      p90_ms: percentile(values, 0.90),
      p99_ms: percentile(values, 0.99),
    }))
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

  return {
    window_days: windowDays,
    window_start: new Date(windowStartMs).toISOString(),
    window_end: new Date(nowMs).toISOString(),
    completion: {
      scans: scans.size,
      complete: completed,
      completion_loss: completionLoss,
      completion_rate_pct: scans.size === 0
        ? 0
        : Number(((completed / scans.size) * 100).toFixed(2)),
    },
    failure_attribution: failureAttribution,
    latency_percentiles: latencyPercentiles,
    co_failure: {
      scans_with_both_providers_attempted: bothAttempted,
      both_providers_failed: bothFailed,
      co_failure_rate_pct: bothAttempted === 0
        ? 0
        : Number(((bothFailed / bothAttempted) * 100).toFixed(2)),
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
