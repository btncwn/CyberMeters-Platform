// ── Daily operational counters and response observation ─────────────────────
//
// Every API response passes observeApiResponse() (index.js json helper):
//   - any refusal (status >= 400) becomes one METRICS data point with the status,
//     the response code and the route family: the "silent rejection" counter.
//     Analytics Engine only, so a flood of refusals costs no D1 writes;
//   - a 5xx, a free-scan answer and a free-tool answer also increment a D1 daily
//     counter, which the founder's 08:00 email reads.
// Labels are fixed vocabulary or route families with identifiers replaced by
// ":id". No domain, IP, email, token or free text is ever recorded.
import { recordMetric } from "./metrics.js";

const CODE = /^[a-z0-9_.-]{1,64}$/;
const MAX_LABELS_PER_METRIC_DAY = 500;

export function utcDay(nowMs = Date.now()) {
  return new Date(nowMs).toISOString().slice(0, 10);
}

/** /api/workspaces/ws_123/scans/scan_9 -> /api/workspaces/:id/scans/:id */
export function routeFamily(pathname) {
  const segments = String(pathname || "/").split("?")[0].split("/").filter(Boolean).slice(0, 6);
  const family = segments.map((segment) => {
    if (/^[a-z][a-z-]{0,40}$/.test(segment)) return segment;
    return ":id";
  });
  return `/${family.join("/")}`.slice(0, 120);
}

export function safeCode(value) {
  const text = typeof value === "string" ? value.trim().toLowerCase() : "";
  return CODE.test(text) ? text : null;
}

/** Add n to today's (metric, label). Fail-open: observation never breaks a request. */
export async function bumpDailyCounter(env, metric, label, n = 1, nowMs = Date.now()) {
  const db = env?.cybermeters_db;
  if (!db || !CODE.test(metric) || typeof label !== "string" || !label || label.length > 200) return false;
  const day = utcDay(nowMs);
  try {
    // A new label is admitted only while the day's label count for this metric
    // is under its cap, so an unexpected label stream cannot grow the table.
    const result = await db.prepare(
      `INSERT INTO ops_daily_counters (day, metric, label, count, updated_at)
       SELECT ?, ?, ?, ?, ?
        WHERE EXISTS (SELECT 1 FROM ops_daily_counters WHERE day = ? AND metric = ? AND label = ?)
           OR (SELECT COUNT(*) FROM ops_daily_counters WHERE day = ? AND metric = ?) < ?
       ON CONFLICT(day, metric, label) DO UPDATE SET
         count = ops_daily_counters.count + excluded.count,
         updated_at = excluded.updated_at`,
    ).bind(day, metric, label, n, new Date(nowMs).toISOString(), day, metric, label, day, metric,
      MAX_LABELS_PER_METRIC_DAY).run();
    return Number(result?.meta?.changes ?? 0) > 0;
  } catch {
    return false;
  }
}

function freeToolLabel(pathname, data, status) {
  const match = String(pathname).match(/^\/api\/tools\/([a-z]+)\/check$/);
  if (!match) return null;
  const outcome = status === 200
    ? `ok_${safeCode(data?.result?.verdict?.level) || "unknown"}${data?.cached ? "_cached" : ""}`
    : safeCode(data?.status) || safeCode(data?.code) || String(status);
  return `${match[1]}:${outcome}`;
}

function freeScanLabel(data, status) {
  if (status === 200) return `ok_${safeCode(data?.preview_state) || "unknown"}`;
  return safeCode(data?.code) || String(status);
}

/**
 * Called with every JSON response the API builds. Returns the D1 write as a
 * promise (or null); the caller hands it to ctx.waitUntil.
 */
export function observeApiResponse(env, { pathname, method, status, data }) {
  const family = routeFamily(pathname);
  const code = safeCode(data?.code) || safeCode(data?.error) || "none";
  if (status >= 400) {
    recordMetric(env, "api_rejection", {
      blobs: [String(status), code, family, String(method || "")],
      doubles: [1],
      indexes: [`${status}:${code}`],
    });
  }
  const writes = [];
  if (status >= 500) writes.push(bumpDailyCounter(env, "http_5xx", `${status}:${family}`.slice(0, 200)));
  if (pathname === "/api/free-scan" && method === "POST") writes.push(bumpDailyCounter(env, "free_scan", freeScanLabel(data, status)));
  const tool = method === "POST" ? freeToolLabel(pathname, data, status) : null;
  if (tool) writes.push(bumpDailyCounter(env, "free_tool", tool));
  return writes.length ? Promise.all(writes) : null;
}

/** Yesterday's and the previous seven days' counters for one metric. */
export async function readDailyCounters(env, metric, fromDay, toDay) {
  const rows = await env.cybermeters_db.prepare(
    `SELECT day, label, count FROM ops_daily_counters
      WHERE metric = ? AND day >= ? AND day <= ? ORDER BY day ASC, count DESC LIMIT 2000`,
  ).bind(metric, fromDay, toDay).all();
  return rows?.results || [];
}
