// ── F-027: scan DLQ observer (a DISTINCT consumer, never the scan engine) ─────
// The scan-dispatch dead-letter queue previously had NO consumer — a dead-lettered
// scan was only reconciled later by the hourly recovery path. This observer gives
// it a durable, safe operational footprint the moment it dead-letters, WITHOUT ever
// running the scan engine on it (a DLQ message is a give-up signal, not work to
// retry through the engine — re-running it here would loop the failure).
//
// Ordering is the honesty core (contract item 2): PERSIST BEFORE ACK. A message is
// acked ONLY after its operational event is durably written. If the write fails the
// message is NOT acked (retry: Cloudflare redelivers), so a persistence outage can
// never silently swallow a DLQ observation. Idempotency (derived id on
// event_type+correlation_id) makes redelivery safe — one dead-letter, one row.

import { persistOperationalEvent, OPS_EVENT_TYPES } from "../lib/operational-events.js";

// A safe correlation id for a DLQ message: prefer the platform scan id from the
// message body, else the queue message id. Both are opaque platform identifiers,
// never customer content; anything non-token-safe falls back to the message id.
const SAFE_TOKEN = /^[\w:.\-]{1,200}$/;
function safeCorrelationId(message) {
  const scanId = message?.body?.scanId ?? message?.body?.scan_id ?? null;
  if (typeof scanId === "string" && SAFE_TOKEN.test(scanId)) return scanId;
  const msgId = message?.id;
  if (typeof msgId === "string" && SAFE_TOKEN.test(msgId)) return msgId;
  return `dlq:${String(msgId ?? "unknown").replace(/[^\w:.\-]/g, "").slice(0, 64) || "unknown"}`;
}

/**
 * Handle one batch from the scan DLQ. NEVER dispatches to the scan engine.
 * Each message: persist its operational event, and ack ONLY on durable success;
 * a failed persist leaves the message un-acked for redelivery. Returns a small
 * summary for observability/tests.
 */
export async function handleScanDlqBatch(batch, env) {
  const messages = Array.isArray(batch?.messages) ? batch.messages : [];
  let observed = 0, deferred = 0;
  for (const message of messages) {
    const correlationId = safeCorrelationId(message);
    const attempts = Number.isInteger(message?.attempts) && message.attempts > 0
      ? message.attempts : 1;
    const result = await persistOperationalEvent(env, {
      eventType:     OPS_EVENT_TYPES.SCAN_DLQ_OBSERVED,
      correlationId,
      status:        "observed",
      attempts,
    });
    if (result.persisted) {
      message.ack?.();       // durable — safe to ack
      observed += 1;
    } else {
      message.retry?.();     // NOT persisted — no-ack, redeliver (fail closed)
      deferred += 1;
    }
  }
  return { queue: batch?.queue ?? null, observed, deferred, total: messages.length };
}
