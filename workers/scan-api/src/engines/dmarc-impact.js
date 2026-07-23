// ── DMARC policy impact forecast + post-change monitor ─────────────────────
// Read-only, deterministic impact calculations over DMARC aggregate records.
// Windows use dmarc_aggregate_reports.date_range_begin (mail period), not record
// ingest time. Manual sender classification is translated into the observed
// vocabulary by the canonical resolver when classified_at is set.
import { resolveEffectiveClassification } from "./sender-classification.js";
import { dmarcAuthoritySourceSql } from "../lib/dmarc-authority.js";
import { aggregateReportCompleteSql } from "../lib/aggregate-report-ingest.js";

export const IMPACT_MIN_MESSAGES = 50;
export const IMPACT_WINDOW_DAYS = 7;
export const ROLLBACK_LEGIT_FAIL_PP = 2;
export const LEGIT_CLASSES = new Set(["authorised", "likely_authorised", "forwarder", "mailing_list"]);

function toEpochSeconds(value, fallback = Math.floor(Date.now() / 1000)) {
  if (value == null) return fallback;
  if (typeof value === "number" && Number.isFinite(value)) {
    return value > 10_000_000_000 ? Math.floor(value / 1000) : Math.floor(value);
  }
  const ms = new Date(String(value)).getTime();
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : fallback;
}

function clampPct(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 100;
  return Math.max(0, Math.min(100, Math.round(n)));
}

function round1(value) {
  return Math.round(Number(value || 0) * 10) / 10;
}

// This module used to carry its own private copy of this mapping — and it was the
// only one of the three that had it RIGHT. It is now imported from the single
// authority (sender-classification.js) so the lifecycle engine, rua-routing and this
// module can never disagree about what a customer's word means again.
//
// Behaviour here is unchanged: trusted→authorised, suspicious→suspicious,
// threat→unauthorised. The shared resolver additionally refuses to pass an
// unrecognised value straight through as if it were evidence, and treats `ignored`
// as claiming nothing rather than as a verdict.
const effectiveClassification = (row = {}) => resolveEffectiveClassification(row);

function isLegitimateClassification(classification) {
  return LEGIT_CLASSES.has(classification);
}

async function loadImpactRows(env, workspaceId, domain, { startEpoch, endEpoch } = {}) {
  const rows = await env.cybermeters_db
    .prepare(`SELECT r.source_ip,
                     COALESCE(s.provider_guess, 'unknown') AS provider,
                     s.classification, s.auto_classification, s.classified_at,
                     SUM(r.message_count) AS total_messages,
                     SUM(CASE WHEN r.dkim_aligned_result = 'pass' OR r.spf_aligned_result = 'pass'
                              THEN r.message_count ELSE 0 END) AS aligned_messages,
                     SUM(CASE WHEN r.dkim_aligned_result = 'pass' OR r.spf_aligned_result = 'pass'
                              THEN 0 ELSE r.message_count END) AS failed_messages
              FROM dmarc_aggregate_records r
              JOIN dmarc_aggregate_reports rep
                ON rep.id = r.report_id
               AND rep.workspace_id = r.workspace_id
               AND rep.domain = r.domain
              LEFT JOIN email_sender_sources s
                ON s.workspace_id = r.workspace_id
               AND s.domain = r.domain
               AND s.source_ip = r.source_ip
              WHERE r.workspace_id = ? AND r.domain = ?
                AND ${aggregateReportCompleteSql("rep", "dmarc")}
                AND rep.date_range_begin IS NOT NULL
                AND rep.date_range_begin >= ?
                AND rep.date_range_begin < ?
                AND ${dmarcAuthoritySourceSql("rep")}
              GROUP BY r.source_ip, s.provider_guess, s.classification, s.auto_classification, s.classified_at`)
    .bind(workspaceId, domain, startEpoch, endEpoch).all();
  return rows.results || [];
}

function summarizeWindow(rows = []) {
  let total = 0, aligned = 0, failed = 0, legitimateFailed = 0, unknownMessages = 0;
  for (const row of rows) {
    const rowTotal = Number(row.total_messages || 0);
    const rowAligned = Number(row.aligned_messages || 0);
    const rowFailed = Number(row.failed_messages || 0);
    const classification = effectiveClassification(row);
    total += rowTotal;
    aligned += rowAligned;
    failed += rowFailed;
    if (isLegitimateClassification(classification)) legitimateFailed += rowFailed;
    if (classification === "unknown") unknownMessages += rowTotal;
  }
  return {
    total_messages: total,
    aligned_messages: aligned,
    failed_messages: failed,
    legitimate_failed_messages: legitimateFailed,
    unknown_messages: unknownMessages,
    aligned_rate: total > 0 ? round1((aligned / total) * 100) : 0,
    failed_rate: total > 0 ? round1((failed / total) * 100) : 0,
    legitimate_failed_rate: total > 0 ? round1((legitimateFailed / total) * 100) : 0,
    insufficient_data: total < IMPACT_MIN_MESSAGES,
  };
}

export async function forecastPolicyImpact(env, workspaceId, domain, {
  targetPolicy = "reject", targetPct = 100, windowDays = IMPACT_WINDOW_DAYS, now = new Date(),
} = {}) {
  const endEpoch = toEpochSeconds(now);
  const days = Math.max(1, Number(windowDays || IMPACT_WINDOW_DAYS));
  const startEpoch = endEpoch - Math.floor(days * 86400);
  const rows = await loadImpactRows(env, workspaceId, domain, { startEpoch, endEpoch });
  const pct = String(targetPolicy || "").toLowerCase() === "none" ? 0 : clampPct(targetPct);
  const multiplier = pct / 100;
  let totalMessages = 0, affectedMessages = 0, legitimateAffected = 0;
  const legitimateSenders = [];

  for (const row of rows) {
    const total = Number(row.total_messages || 0);
    const failed = Number(row.failed_messages || 0);
    const affected = Math.round(failed * multiplier);
    const classification = effectiveClassification(row);
    totalMessages += total;
    affectedMessages += affected;
    if (isLegitimateClassification(classification)) {
      legitimateAffected += affected;
      if (affected > 0) legitimateSenders.push({
        source_ip: row.source_ip,
        provider: row.provider || "unknown",
        classification,
        affected,
      });
    }
  }

  legitimateSenders.sort((a, b) => b.affected - a.affected);
  return {
    target_policy: targetPolicy,
    target_pct: pct,
    window_days: days,
    total_messages: totalMessages,
    affected_messages: affectedMessages,
    affected_percentage: totalMessages > 0 ? round1((affectedMessages / totalMessages) * 100) : 0,
    legitimate_affected_messages: legitimateAffected,
    legitimate_affected_senders: legitimateSenders.slice(0, 10),
    risky_affected_messages: Math.max(0, affectedMessages - legitimateAffected),
    insufficient_data: totalMessages < IMPACT_MIN_MESSAGES,
  };
}

export async function comparePolicyImpact(env, workspaceId, domain, {
  changeAt, windowDays = IMPACT_WINDOW_DAYS, now = new Date(),
} = {}) {
  const changeEpoch = toEpochSeconds(changeAt);
  const nowEpoch = Math.max(changeEpoch, toEpochSeconds(now));
  const days = Math.max(1, Number(windowDays || IMPACT_WINDOW_DAYS));
  const beforeStart = changeEpoch - Math.floor(days * 86400);
  const beforeRows = await loadImpactRows(env, workspaceId, domain, { startEpoch: beforeStart, endEpoch: changeEpoch });
  const afterRows = await loadImpactRows(env, workspaceId, domain, { startEpoch: changeEpoch, endEpoch: nowEpoch + 1 });
  const before = summarizeWindow(beforeRows);
  const after = summarizeWindow(afterRows);
  const delta = {
    legitimate_failed_rate_increase: round1(after.legitimate_failed_rate - before.legitimate_failed_rate),
    aligned_rate_change: round1(after.aligned_rate - before.aligned_rate),
    failed_rate_change: round1(after.failed_rate - before.failed_rate),
    total_messages_change: after.total_messages - before.total_messages,
    unknown_messages_change: after.unknown_messages - before.unknown_messages,
  };
  return {
    window_days: days,
    change_at: changeAt || null,
    before,
    after,
    delta,
    insufficient_data: after.insufficient_data,
  };
}

export function assessImpactRollback({ before = {}, after = {}, delta = {} } = {}) {
  const increase = Number(delta.legitimate_failed_rate_increase || 0);
  const afterThin = Boolean(after.insufficient_data);
  const triggers = [];
  if (!afterThin && increase > ROLLBACK_LEGIT_FAIL_PP) {
    triggers.push(`Legitimate failed-mail rate increased by ${round1(increase)} percentage points.`);
  }
  let severity = "low";
  if (triggers.length) severity = increase >= 10 ? "critical" : increase >= 5 ? "high" : "medium";
  return {
    rollbackRecommended: triggers.length > 0,
    severity,
    triggers,
    rollbackRecord: triggers.length > 0
      ? "Review the previous managed DMARC value and consider rollback if these senders are legitimate."
      : null,
    insufficient_data: afterThin,
    before,
    after,
    delta,
  };
}
