// ── Observability metrics (Cloudflare Analytics Engine, fail-open) ────────────
// Writes one data point to the METRICS dataset when the binding is present.
// Observability must never break a request or a cron task, so a missing binding
// is a silent no-op and every failure is swallowed. Convention: blobs[0] = event
// name; indexes[0] = the sampling key. When env.WORKER_NAME is set (the split
// workers from Sprint 10), it is appended as the TRAILING blob so one shared
// dataset answers "which worker" — additive: workers without the var (the api
// worker today) emit exactly the same datapoints as before.
export function recordMetric(env, event, { blobs = [], doubles = [], indexes = [] } = {}) {
  try {
    env?.METRICS?.writeDataPoint?.({
      blobs: [
        String(event),
        ...blobs.map((b) => String(b ?? "")),
        ...(env?.WORKER_NAME ? [String(env.WORKER_NAME)] : []),
      ],
      doubles,
      indexes: indexes.map((i) => String(i ?? "")),
    });
  } catch { /* telemetry is best-effort — never throw */ }
}
