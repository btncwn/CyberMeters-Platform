// ── The founder's daily 08:00 email: yesterday, with what changed on top ─────
//
// Read-only. Collects yesterday (UTC) from the daily counters (free scans and
// free tools by outcome, 5xx, browser errors), the account tables (signup →
// verified → first scan → paid) and the feedback inbox, compares the counters
// with the seven days before, and puts anything unusual first. Counts only:
// no domain, email or IP appears in the email; feedback text is quoted as typed.
import { readDailyCounters, utcDay } from "./ops-counters.js";
import { readCanarySince } from "../engines/free-check-canary.js";
import { FREE_SCAN_STATE_LABELS, FREE_SCAN_PREVIEW_BADGES, CUSTOMER_CODE_COPY } from "../../../../shared/customer-labels.js";

const DAY_MS = 86_400_000;
// An anomaly needs both: at least this many events, and this many times the
// average of the seven days before (or any events where there were none).
const ANOMALY_MIN = 5;
const ANOMALY_RATIO = 2;

function sum(rows, predicate = () => true) {
  return rows.filter(predicate).reduce((total, row) => total + Number(row.count || 0), 0);
}

function byLabel(rows) {
  const out = new Map();
  for (const row of rows) out.set(row.label, (out.get(row.label) || 0) + Number(row.count || 0));
  return [...out.entries()].sort((a, b) => b[1] - a[1]);
}

async function countOrNull(env, sql, ...args) {
  try {
    const row = await env.cybermeters_db.prepare(sql).bind(...args).first();
    return Number(row?.n ?? 0);
  } catch {
    return null;
  }
}

export async function collectFounderDigest(env, { nowMs = Date.now() } = {}) {
  const yesterday = utcDay(nowMs - DAY_MS);
  const weekStart = utcDay(nowMs - 8 * DAY_MS);
  const weekEnd = utcDay(nowMs - 2 * DAY_MS);
  const from = `${yesterday}T00:00:00.000Z`, to = `${utcDay(nowMs)}T00:00:00.000Z`;
  // users.created_at uses the SQLite default "YYYY-MM-DD HH:MM:SS".
  const fromSql = `${yesterday} 00:00:00`, toSql = `${utcDay(nowMs)} 00:00:00`;

  const metrics = {};
  for (const metric of ["free_scan", "free_tool", "http_5xx", "client_error"]) {
    let rows = [];
    try { rows = await readDailyCounters(env, metric, weekStart, yesterday); } catch { rows = null; }
    if (rows === null) { metrics[metric] = null; continue; }
    const day = rows.filter((row) => row.day === yesterday);
    const week = rows.filter((row) => row.day >= weekStart && row.day <= weekEnd);
    metrics[metric] = { total: sum(day), weekAverage: sum(week) / 7, labels: byLabel(day) };
  }

  const funnel = {
    signups: await countOrNull(env, "SELECT COUNT(*) AS n FROM users WHERE created_at >= ? AND created_at < ? AND email NOT LIKE 'deleted\\_%' ESCAPE '\\'", fromSql, toSql),
    verified: await countOrNull(env, "SELECT COUNT(*) AS n FROM users WHERE created_at >= ? AND created_at < ? AND email_verified = 1 AND email NOT LIKE 'deleted\\_%' ESCAPE '\\'", fromSql, toSql),
    scanned: await countOrNull(env, `SELECT COUNT(DISTINCT u.id) AS n FROM users u
      JOIN workspaces w ON w.owner_user_id = u.id JOIN scans s ON s.workspace_id = w.id
      WHERE u.created_at >= ? AND u.created_at < ? AND u.email NOT LIKE 'deleted\\_%' ESCAPE '\\'`, fromSql, toSql),
    paid: await countOrNull(env, `SELECT COUNT(*) AS n FROM subscriptions
      WHERE stripe_subscription_id IS NOT NULL AND subscription_status = 'active'
        AND created_at >= ? AND created_at < ?`, fromSql, toSql),
  };

  let feedback = null;
  try {
    const rows = await env.cybermeters_db.prepare(
      `SELECT created_at, surface, tool, path, error_code, message FROM feedback_reports
        WHERE created_at >= ? AND created_at < ? ORDER BY created_at ASC LIMIT 50`,
    ).bind(from, to).all();
    feedback = rows?.results || [];
  } catch { feedback = null; }

  // This morning's free-check canary (07:00 UTC, engines/free-check-canary.js).
  let canary = null;
  try { canary = await readCanarySince(env, `${utcDay(nowMs)}T00:00:00.000Z`); } catch { canary = null; }

  const anomalies = [];
  if (canary === null) anomalies.push("Could not read the free-check canary");
  else if (canary.total > 0 && canary.fresh === 0) anomalies.push("The free-check canary did not run this morning");
  else if (canary) {
    for (const row of canary.changed) anomalies.push(`Canary changed: ${row.domain} ${row.previous_fingerprint ?? "(new)"} -> ${row.fingerprint}`);
    for (const row of canary.errors) anomalies.push(`Canary error: ${row.domain} ${row.fingerprint}`);
  }
  const watch = (label, value, average) => {
    if (value >= ANOMALY_MIN && (average === 0 || value >= ANOMALY_RATIO * average)) {
      anomalies.push(`${label}: ${value} yesterday (7-day average ${average.toFixed(1)})`);
    }
  };
  if (metrics.http_5xx) watch("Server errors (5xx)", metrics.http_5xx.total, metrics.http_5xx.weekAverage);
  if (metrics.client_error) watch("Browser error reports", metrics.client_error.total, metrics.client_error.weekAverage);
  for (const metric of ["free_scan", "free_tool"]) {
    const m = metrics[metric];
    if (!m) continue;
    const failed = m.labels.filter(([label]) => !/(^|:)ok_/.test(label)).reduce((t, [, n]) => t + n, 0);
    if (m.total > 0 && failed >= ANOMALY_MIN && failed / m.total >= 0.25) {
      anomalies.push(`${metric === "free_scan" ? "Free scans" : "Free tools"}: ${failed} of ${m.total} did not return a result`);
    }
  }
  for (const [name, value] of Object.entries(metrics)) {
    if (value === null) anomalies.push(`Could not read ${digestLabel(name)} counters`);
  }
  if (Object.values(funnel).some((value) => value === null)) anomalies.push("Could not read the signup funnel");
  if (feedback === null) anomalies.push("Could not read feedback");
  else if (feedback.length > 0) anomalies.unshift(`${feedback.length} feedback message${feedback.length === 1 ? "" : "s"} (below)`);

  return { day: yesterday, metrics, funnel, feedback, canary, anomalies };
}

// Reuse the public preview/reason vocabulary; only digest-specific keys live
// here. Unknown keys remain visible rather than acquiring an invented meaning.
const DIGEST_LABELS = Object.freeze({
  ...CUSTOMER_CODE_COPY,
  ...FREE_SCAN_STATE_LABELS,
  ...FREE_SCAN_PREVIEW_BADGES,
  ...Object.fromEntries(Object.entries(FREE_SCAN_PREVIEW_BADGES).map(([key, label]) =>
    [`ok_${key}`, `${FREE_SCAN_STATE_LABELS.completed} — ${label.toLowerCase()}`])),
  ok_complete: FREE_SCAN_STATE_LABELS.completed,
  ok_unknown: "Completed — result unknown",
  ok_good: "Completed — good result",
  ok_attention: "Completed — needs attention",
  ok_risk: "Completed — risk observed",
  free_scan: "Free scans",
  free_tool: "Free tools",
  http_5xx: "Server errors (5xx)",
  client_error: "Browser error reports",
  app: "App",
  domain_not_found: "Domain not found",
  domain_no_website_address: "Domain has no website address",
  target_verification_unavailable: "Domain verification unavailable",
  rate_limit_exceeded: "Request limit reached",
  rate_limit_unavailable: "Request limiting unavailable",
  limiter_unavailable: "Request limiting unavailable",
  limit_reached: "Daily limit reached",
  capacity_paused: "Checks paused at capacity",
  invalid_input: "Invalid input",
  body_too_large: "Request too large",
  invalid_json: "Unreadable request",
  invalid_domain: "Invalid domain",
  non_public_domain: "Domain is not public",
  verification_required: "Human verification required",
  verification_failed: "Human verification failed",
  verification_unavailable: "Human verification unavailable",
  lookup_failed: "Lookup failed",
  js_error: "JavaScript error",
  unhandled_rejection: "Unhandled promise rejection",
  chunk_load: "Page code could not load",
  api_error: "API request error",
  render_error: "Page rendering error",
  none: "No reason reported",
  spf: "SPF",
  dmarc: "DMARC",
  headers: "Security headers",
  ssl: "SSL/TLS",
  lookalike: "Lookalike domains",
});

function digestLabel(key) {
  return Object.hasOwn(DIGEST_LABELS, key) ? DIGEST_LABELS[key] : `Other (${key})`;
}

function counterLabel(metric, label) {
  if (metric === "http_5xx") {
    const match = /^(\d{3}):(.*)$/.exec(label);
    return match ? `${match[1]} — ${match[2]}` : digestLabel(label);
  }
  if (metric === "client_error") {
    const parts = label.split("|");
    if (parts.length !== 5) return digestLabel(label);
    const [kind, code, status, route, build] = parts;
    return `${digestLabel(kind)} — ${digestLabel(code)} — ${status} — ${route} — ${build}`;
  }
  if (metric === "free_tool") {
    const separator = label.indexOf(":");
    if (separator < 0) return digestLabel(label);
    const tool = label.slice(0, separator), outcome = label.slice(separator + 1);
    const base = outcome.replace(/_cached$/, "");
    const result = outcome.endsWith("_cached") && Object.hasOwn(DIGEST_LABELS, base)
      ? `${digestLabel(base)} (cached)` : digestLabel(outcome);
    return `${digestLabel(tool)} — ${result}`;
  }
  return digestLabel(label);
}

const line = (label, value) => `${label}: ${value ?? "unavailable"}`;

export function formatFounderDigest(digest) {
  const out = [];
  out.push(digest.anomalies.length
    ? ["Needs a look:", ...digest.anomalies.map((a) => `  - ${a}`)].join("\n")
    : "Nothing unusual yesterday.");
  const section = (title, metric) => {
    const m = digest.metrics[metric];
    if (!m) return `${title}: unavailable`;
    const rows = m.labels.slice(0, 12).map(([label, n]) => `  ${counterLabel(metric, label)}: ${n}`);
    return [`${title}: ${m.total} (7-day average ${m.weekAverage.toFixed(1)})`, ...rows].join("\n");
  };
  out.push(section("Free scans by outcome", "free_scan"));
  out.push(section("Free tools by outcome", "free_tool"));
  out.push(section("Server errors (5xx) by route", "http_5xx"));
  out.push(section("Browser errors by type, reason, status, route and build", "client_error"));
  const f = digest.funnel;
  out.push(["Funnel (accounts created yesterday):", `  ${line("Signed up", f.signups)}`, `  ${line("Verified email", f.verified)}`,
    `  ${line("Ran a scan", f.scanned)}`, `  ${line("New paid subscriptions (any age)", f.paid)}`].join("\n"));
  if (digest.canary) {
    out.push(`Free-check canary this morning: ${digest.canary.fresh} of ${digest.canary.total} domains checked, ${digest.canary.changed.length} changed, ${digest.canary.errors.length} errors`);
  }
  if (digest.feedback?.length) {
    out.push(["Feedback:", ...digest.feedback.map((item) =>
      `  [${item.created_at.slice(11, 16)} UTC] ${digestLabel(item.surface)}${item.tool ? `/${item.tool}` : ""} ${item.path}${item.error_code ? ` (${digestLabel(item.error_code)})` : ""}\n    "${item.message.replace(/\s+/g, " ")}"`)].join("\n"));
  }
  const text = `CyberMeters, ${digest.day} (UTC)\n\n${out.join("\n\n")}\n`;
  const subject = `[CyberMeters] Daily: ${digest.anomalies.length ? `${digest.anomalies.length} to look at` : "nothing unusual"} (${digest.day})`;
  return { subject, text };
}
