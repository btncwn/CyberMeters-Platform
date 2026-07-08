// ── Observability metrics (Workers Analytics Engine) ─────────────────────────
// Sprint 9 phase-1: first shared-lib module. Fail-open by design — telemetry
// must never take the worker down.
// ── Observability metrics (Cloudflare Analytics Engine, fail-open) ────────────
// Writes one data point to the METRICS dataset when the binding is present.
// Observability must never break a request or a cron task, so a missing binding
// is a silent no-op and every failure is swallowed. Convention: blobs[0] = event
// name; indexes[0] = the sampling key.
export function recordMetric(env, event, { blobs = [], doubles = [], indexes = [] } = {}) {
  try {
    env?.METRICS?.writeDataPoint?.({
      blobs: [String(event), ...blobs.map((b) => String(b ?? ""))],
      doubles,
      indexes: indexes.map((i) => String(i ?? "")),
    });
  } catch { /* telemetry is best-effort — never throw */ }
}
