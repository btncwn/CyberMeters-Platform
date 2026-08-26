// ── F-027 internal observability: append-only operational-event ledger ────────
// Durable, CUSTOMER-SAFE records of platform-health facts (DLQ observations,
// cron ticks, alert-delivery failures) that /ready and the deadman monitor read.
// The table is append-only and tenant-isolated (mig 108). This module is the ONE
// writer/reader boundary so the safety rules cannot be bypassed at a call site:
//
//   • SAFE FIELDS ONLY. event_type, a safe correlation_id, status, attempts.
//     NEVER a raw message body, email address, or error prose — a correlation id
//     is an opaque platform identifier (scan id, "cron:name:hourBucket",
//     message id), never customer content.
//   • IDEMPOTENT. (event_type, correlation_id) is UNIQUE; a redelivered consumer
//     INSERT OR IGNOREs, so one logical event is one row regardless of retries.
//     The id is DERIVED from (event_type, correlation_id), not random, so the
//     same logical event maps to the same primary key across redeliveries.
//   • FAIL CLOSED. persistOperationalEvent reports whether the write durably
//     landed; a caller that must not ack before persistence checks the result
//     and no-acks on failure (never a silent success).

const OPS_EVENT_TYPES = Object.freeze({
  SCAN_DLQ_OBSERVED:     "scan_dlq_observed",
  CRON_TICK:             "cron_tick",
  ALERT_DELIVERY_FAILED: "alert_delivery_failed",
});

// Deterministic id from the idempotency key — same logical event, same PK.
async function derivedEventId(eventType, correlationId) {
  const data = new TextEncoder().encode(`${eventType} ${correlationId}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `opev_${hex.slice(0, 32)}`;
}

// Reject any field that could smuggle customer content. correlation_id/status/
// event_type must be short, printable, control-char-free tokens; attempts an int.
const SAFE_TOKEN = /^[\w:.\-]{1,200}$/;
function isSafeToken(value) {
  return typeof value === "string" && SAFE_TOKEN.test(value);
}

/**
 * Persist ONE operational event before the caller acks its work.
 * @returns {Promise<{persisted: boolean, reason?: string, id?: string}>}
 *          persisted:true only when the row is durably present (inserted OR an
 *          idempotent duplicate already there). persisted:false = the caller
 *          MUST NOT treat its work as done (retry / no-ack).
 */
export async function persistOperationalEvent(env, {
  eventType, correlationId, status, attempts = 1, workspaceId = null,
} = {}) {
  if (!isSafeToken(eventType) || !isSafeToken(correlationId) || !isSafeToken(status)) {
    return { persisted: false, reason: "unsafe_or_missing_field" };
  }
  const attemptCount = Number.isInteger(attempts) && attempts > 0 ? attempts : 1;
  const wsId = workspaceId == null ? null : (isSafeToken(workspaceId) ? workspaceId : null);
  const db = env?.cybermeters_db;
  if (!db?.prepare) return { persisted: false, reason: "db_unavailable" };

  try {
    const id = await derivedEventId(eventType, correlationId);
    // INSERT OR IGNORE = idempotent on the UNIQUE(event_type, correlation_id).
    const res = await db
      .prepare(
        `INSERT OR IGNORE INTO operational_events
           (id, workspace_id, event_type, correlation_id, status, attempts)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
      .bind(id, wsId, eventType, correlationId, status, attemptCount)
      .run();
    // changes===0 means the idempotent duplicate already exists — still durable.
    if (res?.success !== false) return { persisted: true, id };
    return { persisted: false, reason: "insert_failed" };
  } catch {
    // No raw error prose leaves this boundary.
    return { persisted: false, reason: "insert_threw" };
  }
}

/**
 * Newest event of a type (freshness reads for /ready + deadman). Platform-level
 * read: not tenant-scoped, returns only safe columns.
 */
export async function latestOperationalEvent(env, eventType) {
  const db = env?.cybermeters_db;
  if (!db?.prepare || !isSafeToken(eventType)) return null;
  try {
    return await db
      .prepare(
        `SELECT event_type, correlation_id, status, attempts, created_at
           FROM operational_events
          WHERE event_type = ?
          ORDER BY created_at DESC
          LIMIT 1`
      )
      .bind(eventType).first();
  } catch { return null; }
}

/**
 * Count events of a type within the last N minutes, DISTINGUISHING a read failure
 * from a proven zero (F-027 R1-02). A caught D1 error returning a fabricated 0 lies:
 * an unmeasured window is not a measured-empty window. This reports readability
 * explicitly so the caller can fail closed on an unreadable signal.
 * @returns {Promise<{readable: boolean, count: number|null}>}
 *          readable:false + count:null when the window could not be read.
 */
export async function readRecentOperationalEventCount(env, eventType, withinMinutes) {
  const db = env?.cybermeters_db;
  if (!db?.prepare || !isSafeToken(eventType)) return { readable: false, count: null };
  const mins = Number.isFinite(withinMinutes) && withinMinutes > 0 ? withinMinutes : 60;
  try {
    const row = await db
      .prepare(
        `SELECT COUNT(*) AS n FROM operational_events
          WHERE event_type = ?
            AND created_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now', ?)`
      )
      .bind(eventType, `-${mins} minutes`).first();
    return { readable: true, count: Number(row?.n || 0) };
  } catch { return { readable: false, count: null }; }
}

/**
 * Count events of a type within the last N minutes (recent-DLQ signal). Backward-
 * compatible numeric wrapper over readRecentOperationalEventCount: an unreadable
 * window collapses to 0 HERE, so a caller that must tell a read FAILURE apart from
 * a proven zero uses readRecentOperationalEventCount directly.
 */
export async function countRecentOperationalEvents(env, eventType, withinMinutes) {
  const r = await readRecentOperationalEventCount(env, eventType, withinMinutes);
  return r.readable ? r.count : 0;
}

// ── Alert-delivery outcome (contract item 3) ─────────────────────────────────
// A sendAlertEmail result that is NOT a confirmed send becomes a DURABLE
// delivery-failure event — REPLACING the old silent `.catch(() => {})`. A thrown
// sender and a returned `{ sent:false }` fail closed to the same record. Returns
// whether a failure was recorded (false = the send succeeded, nothing to record).
export async function recordAlertDeliveryOutcome(env, sendResult, correlationId) {
  if (sendResult && sendResult.sent === true) return { recorded: false };
  const reason = typeof sendResult?.reason === "string" ? sendResult.reason : "unknown";
  const res = await persistOperationalEvent(env, {
    eventType:     OPS_EVENT_TYPES.ALERT_DELIVERY_FAILED,
    correlationId,
    status:        reason,
  });
  return { recorded: true, reason, persisted: res.persisted };
}

// ── Queue dispatch by identity (contract item 1) ─────────────────────────────
// The scan DLQ routes to the observer; every other queue is scan-dispatch work.
// A dead-letter must NEVER reach the scan engine, so this is an explicit
// allow-by-identity, not a default-through.
export const SCAN_DLQ_NAME = "cybermeters-scan-dlq";
export function resolveQueueConsumer(queueName) {
  return queueName === SCAN_DLQ_NAME ? "dlq_observer" : "scan_dispatch";
}

// The queue-handler body, extracted so it is EXECUTABLE and its behaviour (not a
// text shape) can be asserted: the DLQ goes to the observer and NEVER the engine;
// every other queue runs the scan-dispatch handler WITH the scheduled settlement
// hook injected. `handlers` supplies { dlq, dispatch, settle } so a test can
// observe both the routing decision and the injected hook without the Worker.
export function routeQueueBatch(batch, env, ctx, handlers = {}) {
  const { dlq, dispatch, settle } = handlers;
  if (resolveQueueConsumer(batch?.queue) === "dlq_observer") {
    return dlq(batch, env);
  }
  return dispatch(batch, env, ctx, { onScheduledScanSettled: settle });
}

export { OPS_EVENT_TYPES };
