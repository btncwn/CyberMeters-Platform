// ── Durable manual-scan Queue dispatch (PR-3A, 22 Jul 2026) ──────────────────
// Producer + consumer for the manual-scan Cloudflare Queue lifecycle:
//
//   POST /api/scan → atomic 099 admission (status 'queued') → dispatchAdmittedScan
//   (R2 queued placeholder + SCAN_QUEUE.send) → 202 → queue() consumer →
//   claim CAS queued→running → runScanEngine → terminal finalisation (engine).
//
// INERT until SCAN_DISPATCH_MODE = "queue" (PR-3B cutover, founder-gated): any
// other value — including absent — fails safe to the existing waitUntil path,
// and the consumer receives nothing because the producer never sends.
//
// Trust boundary: delivery is AT-LEAST-ONCE and the message body is advisory.
// Only scan_id is execution-authoritative — the consumer re-reads the scans row
// and derives tenant/domain identity from D1. Advisory fields are cross-checked
// and a mismatch fails CLOSED (no execution, sanitised audit, ack). The claim
// CAS (`... WHERE id = ? AND status = 'queued'`) is the single execution gate:
// exactly one delivery can win it, so a duplicate delivery, a replay, or a
// message arriving after PR-1 recovery already terminalised the row is always
// a no-op. Every non-idempotent side-effect writer in the engine runs strictly
// AFTER terminal finalisation, so a redelivery can never double-run them.
//
// Engine failures are NEVER queue-retried: runScanEngine's own catch finalises
// an honest terminal 'failed' (the canonical latch), so a retry could only burn
// deliveries to reach the same terminal state. Queue retries cover only
// pre-claim transients (D1 read failure, deploy-skew version) — the row is
// still honestly 'queued' then, so no 'retrying' status is ever persisted in
// v1 and Queue delivery metadata (message.attempts) stays authoritative.

import { runScanEngine, heartbeatScan } from "./scan-engine.js";
import { createAuditEvent } from "../lib/events.js";
import { createId } from "../lib/util.js";

export const SCAN_DISPATCH_MESSAGE_VERSION = 1;

// Bounded retry delays (seconds). Deploy-skew (a newer producer's message
// reaching this consumer) resolves on the next deploy — back off long; a
// transient D1 read failure resolves quickly — back off short.
export const UNKNOWN_VERSION_RETRY_DELAY_S = 300;
export const TRANSIENT_RETRY_DELAY_S = 60;

export const DISPATCH_FAILED_REASON = "dispatch_failed";
export const DISPATCH_FAILED_CUSTOMER_MESSAGE =
  "This scan could not be started. No results were recorded. Please try again.";
export const QUEUED_PLACEHOLDER_MESSAGE =
  "Scan queued for execution. Poll GET /api/scans/:id for progress.";

const TERMINAL_STATUSES = new Set(["completed", "failed"]);

// The ONE mode switch. Fail-safe: anything but the exact string "queue"
// (absent, empty, typo) keeps the existing waitUntil path.
export function isQueueDispatchMode(env = {}) {
  return env?.SCAN_DISPATCH_MODE === "queue";
}

// Version-1 message. scan_id is the only execution-authoritative field; the
// rest is advisory (cross-checked by the consumer) or correlation-only.
export function buildScanDispatchMessage({ scanId, workspaceId, domainId, domain, userId, requestId }) {
  return {
    v: SCAN_DISPATCH_MESSAGE_VERSION,
    scan_id: scanId,
    workspace_id: workspaceId ?? null,
    domain: domain ?? null,
    domain_id: domainId ?? null,
    user_id: userId ?? null,
    trigger: "manual",
    admitted_at: new Date().toISOString(),
    request_id: requestId ?? createId("req"),
  };
}

// Sanitised structured log line — scan/request ids and stable reason codes
// only; never error messages (which can carry SQL/query fragments), never
// customer data. Wrapped so logging can never break dispatch.
function dispatchLog(fields) {
  try { console.log("[scan-dispatch]", JSON.stringify(fields)); } catch { /* never fatal */ }
}

// ── Producer: dispatch setup for an ADMITTED 'queued' row ────────────────────
// R2 queued-placeholder + Queue.send form ONE compensation boundary: if either
// fails after the atomic admission, the row is CAS-failed (queued→failed only —
// never clobbering a state some other actor moved it to), a canonical failed
// report is written when R2 itself is reachable, one scan_dispatch_failed audit
// is appended, and the caller returns a customer-safe 503. If the compensating
// D1 write itself fails, the stale 'queued' row is deliberately LEFT for the
// hourly PR-1 recovery path to converge — never reported as success.
export async function dispatchAdmittedScan(env, { scanId, domainId, workspaceId, userId, domain, reportKey }) {
  const requestId = createId("req");
  let stage = "r2_placeholder";
  try {
    // Canonical quality invariant (PR-1b): a queued scan has earned neither
    // `complete` nor `partial` — scan_quality is NULL until terminal finalisation.
    await env.cybermeters_reports.put(
      reportKey,
      JSON.stringify({
        scan_id:             scanId,
        domain_id:           domainId,
        domain,
        status:              "queued",
        cyber_metrics_score: 0,
        risk_level:          "unknown",
        findings:            [],
        recommendations:     [],
        scan_quality:        null,
        message:             QUEUED_PLACEHOLDER_MESSAGE,
      }, null, 2),
      { httpMetadata: { contentType: "application/json" } }
    );

    stage = "queue_send";
    await env.SCAN_QUEUE.send(
      buildScanDispatchMessage({ scanId, workspaceId, domainId, domain, userId, requestId })
    );

    return { ok: true, request_id: requestId };
  } catch (err) {
    dispatchLog({ scan_id: scanId, request_id: requestId, outcome: "dispatch_failed", stage, error: err?.name || "Error" });

    // Compensation 1 — D1: queued → failed, quality stays NULL. Guarded CAS so
    // a racing actor's transition is never clobbered. A failure here leaves the
    // stale queued row for PR-1 recovery — logged, never fabricated as success.
    try {
      await env.cybermeters_db
        .prepare(`UPDATE scans SET status = 'failed', scan_quality = NULL WHERE id = ? AND status = 'queued'`)
        .bind(scanId)
        .run();
    } catch (compErr) {
      dispatchLog({ scan_id: scanId, request_id: requestId, outcome: "dispatch_compensation_d1_failed", error: compErr?.name || "Error" });
    }

    // Compensation 2 — canonical failed R2 report, only when R2 is reachable
    // (its own try: if R2 was the failure, this likely fails too — we never
    // invent a report over a broken store).
    try {
      await env.cybermeters_reports.put(
        reportKey,
        JSON.stringify({
          scan_id:             scanId,
          domain_id:           domainId,
          domain,
          status:              "failed",
          reason:              DISPATCH_FAILED_REASON,
          cyber_metrics_score: 0,
          risk_level:          "unknown",
          findings:            [],
          recommendations:     [],
          scan_quality:        null,
          failed_at:           new Date().toISOString(),
          message:             DISPATCH_FAILED_CUSTOMER_MESSAGE,
        }, null, 2),
        { httpMetadata: { contentType: "application/json" } }
      );
    } catch { /* R2 unreachable — the D1 terminal (or recovery) owns the truth */ }

    // Compensation 3 — append-only audit evidence. Non-fatal.
    try {
      await createAuditEvent(env, {
        workspace_id: workspaceId ?? null,
        user_id:      userId ?? null,
        event_type:   "scan_dispatch_failed",
        entity_type:  "scan",
        entity_id:    scanId,
        description:  `Scan dispatch failed for ${domain} — the scan was not started`,
        metadata:     { scan_id: scanId, domain, reason: DISPATCH_FAILED_REASON, stage },
      });
    } catch { /* non-fatal */ }

    return { ok: false, request_id: requestId };
  }
}

// ── Consumer: process ONE delivery, returning the outcome decision ───────────
// Exported for deterministic tests; handleScanDispatchBatch applies the
// decision (ack/retry) to the real message. Never throws.
export async function processScanDispatchMessage(body, env, deps = {}) {
  const doRunScanEngine = deps.runScanEngine ?? runScanEngine;
  const doCreateAuditEvent = deps.createAuditEvent ?? createAuditEvent;
  const doHeartbeatScan = deps.heartbeatScan ?? heartbeatScan;

  // ── 1. Validate the envelope. scan_id is mandatory; version must be known. ─
  if (!body || typeof body !== "object" || typeof body.scan_id !== "string" || body.scan_id.length === 0) {
    return { action: "ack", outcome: "malformed" };
  }
  const scanId = body.scan_id;
  if (body.v !== SCAN_DISPATCH_MESSAGE_VERSION) {
    if (Number.isInteger(body.v) && body.v > SCAN_DISPATCH_MESSAGE_VERSION) {
      // Deploy skew: a newer producer wrote this. A newer consumer deployment
      // will understand it — bounded retry, never guess-parse, never fail the scan.
      return { action: "retry", delaySeconds: UNKNOWN_VERSION_RETRY_DELAY_S, outcome: "unknown_version" };
    }
    return { action: "ack", outcome: "malformed" };
  }

  // ── 2. Re-read D1 — the row is the sole execution authority. ──────────────
  let row;
  try {
    row = await env.cybermeters_db
      .prepare(`SELECT id, workspace_id, domain_id, domain, status FROM scans WHERE id = ?`)
      .bind(scanId)
      .first();
  } catch {
    return { action: "retry", delaySeconds: TRANSIENT_RETRY_DELAY_S, outcome: "d1_read_failed" };
  }
  if (!row) return { action: "ack", outcome: "row_missing" };

  // ── 3. Advisory cross-checks — fail CLOSED on any mismatch. ───────────────
  // A mismatch means corruption or forgery; executing anything on it is the
  // wrong side of the trust boundary. The audit carries field NAMES only,
  // never the mismatched values, and attributes to the ROW's tenant.
  const mismatched = [];
  for (const field of ["workspace_id", "domain", "domain_id"]) {
    const advisory = body[field];
    if (typeof advisory === "string" && advisory.length > 0 && advisory !== (row[field] ?? null)) {
      mismatched.push(field);
    }
  }
  if (mismatched.length > 0) {
    try {
      await doCreateAuditEvent(env, {
        workspace_id: row.workspace_id ?? null,
        actor_type:   "system",
        event_type:   "scan_dispatch_mismatch",
        entity_type:  "scan",
        entity_id:    scanId,
        description:  "Scan dispatch message rejected: advisory identity did not match the scan record",
        metadata:     { scan_id: scanId, mismatched_fields: mismatched },
      });
    } catch { /* non-fatal */ }
    return { action: "ack", outcome: "advisory_mismatch" };
  }

  // ── 4. Terminal rows are a no-op (duplicate, replay, post-recovery). ──────
  if (TERMINAL_STATUSES.has(row.status)) {
    return { action: "ack", outcome: "terminal_noop" };
  }

  // ── 5. Claim CAS — the single execution gate. ─────────────────────────────
  // Exactly one delivery flips queued→running; every other delivery (duplicate,
  // simultaneous consumer, redelivery while an execution is in flight) loses
  // the CAS and acks WITHOUT executing. A stale 'running' row is never
  // reclaimed here — PR-1 recovery owns that terminalisation.
  let claim;
  try {
    claim = await env.cybermeters_db
      .prepare(`UPDATE scans SET status = 'running', last_heartbeat_at = ? WHERE id = ? AND status = 'queued'`)
      .bind(new Date().toISOString(), scanId)
      .run();
  } catch {
    return { action: "retry", delaySeconds: TRANSIENT_RETRY_DELAY_S, outcome: "claim_write_failed" };
  }
  if ((claim?.meta?.changes ?? 0) === 0) {
    return { action: "ack", outcome: "claim_lost" };
  }

  // ── 6. Claim won: scan_started audit + queue_claimed heartbeat. ───────────
  // scan_started moves here from the producer (PR-3A): it now records when the
  // engine ACTUALLY starts, and the CAS makes it exactly-once per scan.
  // user_id is advisory correlation from our own producer — acceptable for
  // audit attribution; execution identity still comes only from the row.
  try {
    await doCreateAuditEvent(env, {
      workspace_id: row.workspace_id ?? null,
      user_id:      typeof body.user_id === "string" ? body.user_id : null,
      event_type:   "scan_started",
      entity_type:  "scan",
      entity_id:    scanId,
      description:  `Scan started for ${row.domain}`,
      metadata:     { scan_id: scanId, domain: row.domain, domain_id: row.domain_id, workspace_id: row.workspace_id ?? null },
    });
  } catch { /* non-fatal — an audit failure must not strand a claimed scan */ }
  await doHeartbeatScan(env, scanId, "queue_claimed");

  // ── 7. Execute — awaited INSIDE the queue invocation (full invocation
  // lifetime; never post-response waitUntil). The engine self-finalises
  // completed/failed via the canonical latch; a throw here is a defensive
  // impossibility and is ACKED, never retried — the row converges via the
  // engine's own terminal write or PR-1 recovery.
  try {
    await doRunScanEngine(scanId, row.domain_id, row.workspace_id ?? null, row.domain, env);
    return { action: "ack", outcome: "executed" };
  } catch (err) {
    return { action: "ack", outcome: "engine_error", error: err?.name || "Error" };
  }
}

// ── Consumer entry: the Worker's queue() handler body ────────────────────────
export async function handleScanDispatchBatch(batch, env, ctx, deps = {}) {
  for (const msg of batch?.messages ?? []) {
    const body = msg?.body;
    const decision = await processScanDispatchMessage(body, env, deps);
    dispatchLog({
      scan_id:    typeof body?.scan_id === "string" ? body.scan_id : null,
      request_id: typeof body?.request_id === "string" ? body.request_id : null,
      attempts:   msg?.attempts ?? null,
      outcome:    decision.outcome,
      ...(decision.error ? { error: decision.error } : {}),
    });
    if (decision.action === "retry") {
      msg.retry(decision.delaySeconds != null ? { delaySeconds: decision.delaySeconds } : undefined);
    } else {
      msg.ack();
    }
  }
}
