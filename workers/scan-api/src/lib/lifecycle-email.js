// ── Lifecycle email service ──────────────────────────────────────────────────
// Build/send/dedupe/retry for customer lifecycle email via Resend. Fail-open:
// a failed send is recorded and retried by the hourly cron, never thrown.
import { scanCompletionQualityDisclosure } from "../engines/assessment-presentation.js";
import { createId, isValidEmail, normalizeApiResponseData, pageMeta, paginationParams } from "./util.js";

const EMAIL_SENDER_KEYS = new Set(["ALERT_EMAIL_FROM", "SAFE_EMAIL_FROM", "HELLO_EMAIL_FROM"]);

function normalizeEmailRecipients(toEmails) {
  const values = Array.isArray(toEmails) ? toEmails : typeof toEmails === "string" ? [toEmails] : [];
  const unique = new Map();
  for (const value of values) {
    const email = String(value || "").trim().toLowerCase();
    if (isValidEmail(email)) unique.set(email, email);
  }
  return [...unique.values()];
}

function resolveEmailSender(env, fromKey) {
  if (!EMAIL_SENDER_KEYS.has(fromKey)) return null;
  const sender = String(env[fromKey] || "").trim().toLowerCase();
  return isValidEmail(sender) ? sender : null;
}

function getEmailFrontendOrigin(env) {
  const configured = env.FRONTEND_URL || env.APP_URL || env.ALLOWED_ORIGIN;
  try {
    const parsed = new URL(configured);
    return parsed.protocol === "https:" ? parsed.origin : null;
  } catch {
    return null;
  }
}

function emailDeliveryLog(level, details) {
  // Mask recipient local-parts before logging — logs go to `wrangler tail`, so
  // never leak customer email addresses (PII). Domain is kept for deliverability
  // debugging: "john.doe@acme.com" -> "j***@acme.com".
  const payload = JSON.stringify({ service: "resend", ...details })
    .replace(/([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+)/g, "$1***$2");
  if (level === "error") console.error("[email-delivery]", payload);
  else console.log("[email-delivery]", payload);
}

function prepareEmailDelivery(subject, text, html, env, fromKey, toEmails) {
  const to = normalizeEmailRecipients(toEmails);
  const from = resolveEmailSender(env, fromKey);
  const safeSubject = String(subject || "").replace(/[\r\n]+/g, " ").trim();
  const context = { from_key: fromKey, recipient_count: to.length };

  if (!from) {
    return { ok: false, reason: "invalid_sender", context };
  }
  if (to.length === 0) {
    return { ok: false, reason: "no_valid_recipients", context };
  }
  if (!safeSubject || !String(text || "").trim() || !String(html || "").trim()) {
    return { ok: false, reason: "invalid_content", context };
  }
  const body = JSON.stringify({ from, to, subject: safeSubject, text, html });
  return { ok: true, from, to, subject: safeSubject, text, html, body, context };
}

async function deliverPreparedEmail(prepared, env, {
  idempotencyKey = null,
  apiKey = null,
  readCredential = true,
  lifecycleOutcomeContract = false,
} = {}) {
  const credential = readCredential ? env.RESEND_API_KEY : apiKey;
  if (!credential) {
    emailDeliveryLog("error", { ...prepared.context, outcome: "skipped", reason: "missing_api_key" });
    return { sent: false, reason: "missing_api_key", ...(lifecycleOutcomeContract ? { definitive: true } : {}) };
  }

  try {
    const response = await fetch("https://api.resend.com/emails", {
      method:  "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Bearer ${credential}`,
        ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {}),
      },
      body: prepared.body,
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) {
      // Extract ONLY the provider's machine-readable error code — never the body.
      // Resend's error payload is {name, message, statusCode}; `message` routinely
      // echoes the recipient address, so it is deliberately discarded. `name` is a
      // short slug, and it is length-capped and shape-restricted before it travels
      // any further, so a provider cannot inject prose or PII into our ledger.
      let providerCode = null;
      try {
        const body = await response.json();
        const raw = String(body?.name || "").trim().toLowerCase();
        if (/^[a-z0-9_]{1,64}$/.test(raw)) providerCode = raw;
      } catch { /* non-JSON or empty error body — stay unclassified */ }
      if (!lifecycleOutcomeContract) {
        emailDeliveryLog("error", { ...prepared.context, outcome: "failed", reason: "provider_rejected", status: response.status, provider_code: providerCode });
        return { sent: false, reason: "provider_rejected", status: response.status, provider_code: providerCode };
      }
      if (response.status === 409) {
        const reason = providerCode === "invalid_idempotent_request"
          ? "idempotency_conflict_invalid"
          : providerCode === "concurrent_idempotent_requests"
            ? "idempotency_conflict_concurrent"
            : "idempotency_conflict_unknown";
        emailDeliveryLog("error", { ...prepared.context, outcome: "unknown", reason, status: response.status, provider_code: providerCode });
        return { sent: false, reason, status: response.status, outcomeUnknown: true };
      }
      if (response.status >= 500 || response.status < 400) {
        emailDeliveryLog("error", { ...prepared.context, outcome: "unknown", reason: "provider_server_error", status: response.status, provider_code: providerCode });
        return { sent: false, reason: "provider_server_error", status: response.status, outcomeUnknown: true };
      }
      emailDeliveryLog("error", { ...prepared.context, outcome: "failed", reason: "provider_rejected", status: response.status, provider_code: providerCode });
      return { sent: false, reason: "provider_rejected", status: response.status, provider_code: providerCode, definitive: true };
    }
    let providerId = null;
    try { providerId = (await response.json())?.id || null; } catch { /* response ID is optional */ }
    emailDeliveryLog("info", { ...prepared.context, outcome: "accepted", provider_id: providerId });
    return { sent: true, provider_id: providerId };
  } catch (error) {
    const reason = error?.name === "TimeoutError" ? "timeout" : "network_error";
    emailDeliveryLog("error", {
      ...prepared.context,
      outcome: "unknown",
      reason,
    });
    return lifecycleOutcomeContract
      ? { sent: false, reason, outcomeUnknown: true }
      : { sent: false, reason };
  }
}

async function deliverEmail(subject, text, html, env, fromKey, toEmails) {
  // Preserve the public/generic delivery contract: generic, alert and digest
  // callers do not receive a lifecycle idempotency header.
  const apiKey = env.RESEND_API_KEY;
  const context = { from_key: fromKey, recipient_count: normalizeEmailRecipients(toEmails).length };
  if (!apiKey) {
    emailDeliveryLog("error", { ...context, outcome: "skipped", reason: "missing_api_key" });
    return { sent: false, reason: "missing_api_key" };
  }
  const prepared = prepareEmailDelivery(subject, text, html, env, fromKey, toEmails);
  if (!prepared.ok) {
    emailDeliveryLog("error", { ...prepared.context, outcome: "skipped", reason: prepared.reason });
    return { sent: false, reason: prepared.reason };
  }
  return deliverPreparedEmail(prepared, env, { apiKey, readCredential: false });
}

/**
 * sendCustomerEmail — strict variant for user-facing emails.
 * Unlike sendAlertEmail, this NEVER falls back to env.ALERT_EMAIL_TO.
 * If toEmails is empty or invalid, returns a failed delivery result without sending.
 * Use this for: password reset, workspace alert notifications.
 */
async function sendCustomerEmail(subject, text, html, env, fromKey = "ALERT_EMAIL_FROM", toEmails = null) {
  const to = Array.isArray(toEmails) ? toEmails : [];
  return deliverEmail(subject, text, html, env, fromKey, to);
}

function escapeEmailHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// ── Customer Lifecycle Emails v1 ──────────────────────────────────────────────
// Concise activation emails sent at most once per scope. Idempotency is enforced
// by lifecycle_email_events.dedupe_key (UNIQUE). No secrets, tokens, internal
// IDs or raw errors ever appear in the body; links use FRONTEND_URL only.
const LIFECYCLE_TYPES = new Set([
  "lifecycle_welcome",
  "lifecycle_workspace_created",
  "lifecycle_domain_added",
  "lifecycle_first_scan_completed",
  "lifecycle_email_protection_next_step",
  "lifecycle_payment_failed",
]);

// Pure, testable: a stable dedupe key per (type + scope).
function lifecycleDedupeKey({ type, user_id = null, workspace_id = null, domain = null, ref = null } = {}) {
  const d = String(domain || "").trim().toLowerCase();
  switch (type) {
    case "lifecycle_welcome":                     return `lifecycle_welcome:${user_id || "unknown"}`;
    case "lifecycle_workspace_created":           return `lifecycle_workspace_created:${workspace_id || "unknown"}`;
    case "lifecycle_domain_added":                return `lifecycle_domain_added:${workspace_id || "unknown"}:${d}`;
    case "lifecycle_first_scan_completed":        return `lifecycle_first_scan_completed:${workspace_id || "unknown"}:${d}`;
    case "lifecycle_email_protection_next_step":  return `lifecycle_email_protection_next_step:${workspace_id || "unknown"}:${d}`;
    // One notification per failed invoice (`ref`), not per retry attempt —
    // Stripe fires invoice.payment_failed on every collection retry.
    case "lifecycle_payment_failed":              return `lifecycle_payment_failed:${ref || workspace_id || "unknown"}`;
    default:                                       return `${type}:${user_id || ""}:${workspace_id || ""}:${d}`;
  }
}

const LIFECYCLE_PROVIDER_NOT_STARTED = "provider_not_started";
const LIFECYCLE_SAFE_RETRY_ERRORS = new Set([
  "missing_api_key",
  "invalid_sender",
  "no_valid_recipients",
  "invalid_content",
  "idempotency_key_unavailable",
]);

async function lifecycleProviderIdempotencyKey(dedupeKey) {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(String(dedupeKey)),
  );
  const hex = [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
  if (!/^[a-f0-9]{64}$/.test(hex)) throw new Error("idempotency_key_unavailable");
  return `cybermeters:lifecycle:v1:${hex}`;
}

async function recordLifecyclePreflightFailure(env, { rowId, dedupeKey, workspaceId, reason }) {
  return env.cybermeters_db
    .prepare(`UPDATE lifecycle_email_events
              SET status = 'failed', error = ?, provider_id = NULL
              WHERE id = ? AND dedupe_key = ?
                AND status = 'pending' AND error = 'provider_not_started'
                AND ((? IS NULL AND workspace_id IS NULL) OR workspace_id = ?)`)
    .bind(reason, rowId, dedupeKey, workspaceId, workspaceId)
    .run();
}

async function reclaimLifecycleFailure(env, { rowId, dedupeKey, workspaceId }) {
  return env.cybermeters_db
    .prepare(`UPDATE lifecycle_email_events
              SET status = 'pending', error = 'provider_not_started', provider_id = NULL
              WHERE id = ? AND dedupe_key = ? AND status = 'failed'
                AND ((? IS NULL AND workspace_id IS NULL) OR workspace_id = ?)
                AND created_at > datetime('now', '-3 days')
                AND (
                  error IN ('missing_api_key','invalid_sender','no_valid_recipients','invalid_content','idempotency_key_unavailable')
                  OR (error = 'provider_rejected' AND created_at < datetime('now', '-24 hours'))
                )`)
    .bind(rowId, dedupeKey, workspaceId, workspaceId)
    .run();
}

async function claimLifecycleProviderAttempt(env, {
  rowId,
  dedupeKey,
  workspaceId,
  allowImmediate,
}) {
  return env.cybermeters_db
    .prepare(`UPDATE lifecycle_email_events
              SET status = 'sending', error = NULL
              WHERE id = ? AND dedupe_key = ?
                AND status = 'pending' AND error = 'provider_not_started'
                AND (? = 1 OR created_at < datetime('now', '-15 minutes'))
                AND (
                  (? IS NULL AND workspace_id IS NULL)
                  OR (workspace_id = ? AND EXISTS (
                    SELECT 1 FROM workspaces WHERE id = ? AND deleted_at IS NULL
                  ))
                )`)
    .bind(rowId, dedupeKey, allowImmediate ? 1 : 0, workspaceId, workspaceId, workspaceId)
    .run();
}

async function recordLifecycleProviderOutcome(env, { rowId, dedupeKey, workspaceId, result }) {
  if (result.sent) {
    return env.cybermeters_db
      .prepare(`UPDATE lifecycle_email_events
                SET status = 'sent', provider_id = ?, error = NULL, sent_at = datetime('now')
                WHERE id = ? AND dedupe_key = ? AND status = 'sending'
                  AND ((? IS NULL AND workspace_id IS NULL) OR workspace_id = ?)`)
      .bind(result.provider_id || null, rowId, dedupeKey, workspaceId, workspaceId)
      .run();
  }
  if (result.definitive) {
    return env.cybermeters_db
      .prepare(`UPDATE lifecycle_email_events
                SET status = 'failed', provider_id = NULL, error = ?
                WHERE id = ? AND dedupe_key = ? AND status = 'sending'
                  AND ((? IS NULL AND workspace_id IS NULL) OR workspace_id = ?)`)
      .bind(result.reason, rowId, dedupeKey, workspaceId, workspaceId)
      .run();
  }
  return env.cybermeters_db
    .prepare(`UPDATE lifecycle_email_events
              SET error = ?
              WHERE id = ? AND dedupe_key = ? AND status = 'sending'
                AND ((? IS NULL AND workspace_id IS NULL) OR workspace_id = ?)`)
    .bind(result.reason || "provider_outcome_unknown", rowId, dedupeKey, workspaceId, workspaceId)
    .run();
}

function _lifecycleHtml({ heading, paras, ctaLabel, ctaUrl }) {
  const body = paras.map(p => `<p style="margin:0 0 14px;color:#374151;font-size:14px;line-height:1.6">${p}</p>`).join("");
  const button = ctaUrl
    ? `<p style="margin:6px 0 0"><a href="${ctaUrl}" style="display:inline-block;background:#00876A;color:#ffffff;text-decoration:none;font-weight:600;font-size:14px;padding:10px 18px;border-radius:10px">${escapeEmailHtml(ctaLabel)}</a></p>`
    : "";
  return `<div style="font-family:Inter,Arial,sans-serif;max-width:560px;margin:0 auto;padding:8px">`
    + `<h1 style="font-size:18px;color:#111827;margin:0 0 14px">${escapeEmailHtml(heading)}</h1>`
    + `${body}${button}`
    + `<p style="margin:22px 0 0;color:#9ca3af;font-size:12px">CyberMeters · You are receiving this because you signed up for CyberMeters.</p></div>`;
}

// Pure, testable: build subject + html + text for a lifecycle type. `origin`
// must be an https FRONTEND_URL origin (or null → links omitted). Never embeds
// secrets; user-supplied values (domain, workspace name) are HTML-escaped.
function buildLifecycleEmail(type, { origin = null, wsName = null, domain = null, scanQuality = null } = {}) {
  const link = (path) => (origin ? `${origin}${path}` : null);
  const ws = wsName ? escapeEmailHtml(wsName) : "your workspace";
  const dom = domain ? escapeEmailHtml(domain) : "your domain";
  const DOMAINS_LINE = "Email Protection, Brand Protection, Attack Surface, Certificates &amp; Trust, Cyber Essentials Readiness, Website Security, Identity Exposure and Shadow IT &amp; Unmanaged Technology.";

  let subject, heading, paras, ctaLabel, ctaPath;
  switch (type) {
    case "lifecycle_welcome":
      subject = "Welcome to CyberMeters";
      heading = "Welcome to CyberMeters";
      paras = [
        "CyberMeters helps you understand all eight Cyber MOT domains from one workspace.",
        `The Cyber MOT domains are: ${DOMAINS_LINE}`,
        "To get started, add a domain and run your first Cyber MOT.",
      ];
      ctaLabel = "Open CyberMeters"; ctaPath = "/services";
      break;
    case "lifecycle_workspace_created":
      subject = "Your CyberMeters workspace is ready";
      heading = "Your workspace is ready";
      paras = [
        `Your workspace (${ws}) is set up.`,
        `A workspace connects the Cyber MOT domains: ${DOMAINS_LINE}`,
        "Next, add or confirm a domain to start monitoring it.",
      ];
      ctaLabel = "Add a domain"; ctaPath = "/ws/dashboard";
      break;
    case "lifecycle_domain_added":
      subject = "Your domain is ready for its first scan";
      heading = "Your domain is ready";
      paras = [
        `${dom} has been added to your workspace.`,
        "Run your first scan to map exposed assets and check your email posture.",
        "After that, connect DMARC reporting in Email Protection to see who is sending email using your domain.",
      ];
      ctaLabel = "Run first scan"; ctaPath = "/scans/new";
      break;
    case "lifecycle_first_scan_completed": {
      const quality = scanCompletionQualityDisclosure(scanQuality);
      subject = "Your first CyberMeters scan is complete";
      heading = "Your first scan is complete";
      paras = [
        `Your first scan for ${dom} has finished.`,
        "Review your results: findings are issues worth acting on, while observations are informational signals about your external footprint.",
        ...(quality.disclosure ? [quality.disclosure] : []),
      ];
      ctaLabel = "Review your dashboard"; ctaPath = "/dashboard";
      break;
    }
    case "lifecycle_payment_failed":
      subject = "Action needed: your CyberMeters payment could not be processed";
      heading = "Your payment could not be processed";
      paras = [
        "The latest payment for your CyberMeters subscription could not be processed.",
        "Please update your payment method to keep your paid plan active. The charge will be retried automatically over the next few days.",
        "If payment continues to fail, paid monitoring will stop. Your existing scans, reports and evidence history remain available to view either way.",
      ];
      ctaLabel = "Update payment method"; ctaPath = "/billing";
      break;
    case "lifecycle_email_protection_next_step":
      subject = "Finish connecting DMARC reporting";
      heading = "Finish connecting DMARC reporting";
      paras = [
        `We have started receiving DMARC reports for ${dom}.`,
        "Receiving reports does not mean your DNS is verified. To finish, make sure your DMARC record includes the CyberMeters reporting address, then verify DNS.",
        "Once your record includes the CyberMeters address and DNS is verified, your domain is fully set up.",
      ];
      ctaLabel = "Finish DMARC setup"; ctaPath = "/ws/email-protection";
      break;
    default:
      return { subject: "CyberMeters", html: _lifecycleHtml({ heading: "CyberMeters", paras: ["Open CyberMeters to continue."], ctaLabel: "Open CyberMeters", ctaUrl: link("/services") }), text: "Open CyberMeters to continue." };
  }

  const ctaUrl = link(ctaPath);
  const html = _lifecycleHtml({ heading, paras, ctaLabel, ctaUrl });
  const text = `${heading}\n\n`
    + paras.map(p => p.replace(/&amp;/g, "&")).join("\n\n")
    + (ctaUrl ? `\n\n${ctaLabel}: ${ctaUrl}` : "")
    + `\n\nCyberMeters`;
  return { subject, html, text };
}

/**
 * sendLifecycleEmail — idempotent activation email. Resolves a VERIFIED
 * recipient (explicit `to`, the user, or the workspace owner), dedupes via the
 * UNIQUE dedupe_key, then delivers through the strict customer-email path. Never
 * throws, never sends to unverified/missing addresses, never leaks internals.
 */
async function sendLifecycleEmail(env, {
  type,
  user_id = null,
  workspace_id = null,
  domain = null,
  to = null,
  wsName = null,
  ref = null,
  scan_quality = null,
  _recovery_id = null,
} = {}) {
  let admitted = false;
  let admittedRow = null;
  let admittedDedupeKey = null;
  try {
    if (!LIFECYCLE_TYPES.has(type)) return { skipped: "unknown_type" };

    let email = null, uid = user_id, name = wsName;
    if (to && isValidEmail(String(to).trim().toLowerCase())) email = String(to).trim().toLowerCase();
    if (!email && user_id) {
      const u = await env.cybermeters_db
        .prepare("SELECT id, email, email_verified FROM users WHERE id = ? LIMIT 1").bind(user_id).first();
      if (u?.email_verified && isValidEmail(String(u.email || "").toLowerCase())) email = String(u.email).toLowerCase();
      uid = u?.id ?? user_id;
    }
    if (!email && workspace_id) {
      // deleted_at IS NULL: a soft-deleted workspace must not receive lifecycle
      // email (including failed-email retries within the 3-day window). The
      // "workspace deleted" confirmation is sent separately via sendCustomerEmail
      // with an explicit recipient, so it is unaffected by this filter.
      const row = await env.cybermeters_db
        .prepare("SELECT u.id AS uid, u.email AS email, u.email_verified AS ev, w.name AS wname FROM workspaces w JOIN users u ON u.id = w.owner_user_id WHERE w.id = ? AND w.deleted_at IS NULL LIMIT 1")
        .bind(workspace_id).first();
      if (row?.ev && isValidEmail(String(row.email || "").toLowerCase())) email = String(row.email).toLowerCase();
      uid = uid ?? row?.uid ?? null;
      if (!name) name = row?.wname || null;
    }
    if (!email) return { skipped: "no_verified_email" };

    const dedupeKey = lifecycleDedupeKey({ type, user_id: uid, workspace_id, domain, ref });
    let rowId = createId("lifemail");
    let allowImmediate = true;
    const ins = await env.cybermeters_db
      .prepare(`INSERT INTO lifecycle_email_events (id, user_id, workspace_id, domain, type, dedupe_key, status, error, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', 'provider_not_started', datetime('now'))
                ON CONFLICT(dedupe_key) DO NOTHING`)
      .bind(rowId, uid ?? null, workspace_id ?? null, domain ?? null, type, dedupeKey)
      .run();

    // Only the bounded recovery selector may reclaim an existing row. A live
    // duplicate never turns an ambiguous historical state into resend authority.
    if ((ins.meta?.changes ?? 0) === 0) {
      const existing = await env.cybermeters_db
        .prepare("SELECT id, workspace_id, status, error FROM lifecycle_email_events WHERE dedupe_key = ? LIMIT 1")
        .bind(dedupeKey).first();
      if (!existing || existing.id !== _recovery_id) return { skipped: "duplicate" };
      if ((existing.workspace_id ?? null) !== (workspace_id ?? null)) return { skipped: "duplicate" };
      rowId = existing.id;
      allowImmediate = false;

      if (existing.status === "failed") {
        const safeFailure = LIFECYCLE_SAFE_RETRY_ERRORS.has(existing.error)
          || existing.error === "provider_rejected";
        if (!safeFailure) return { skipped: "duplicate" };
        const reclaim = await reclaimLifecycleFailure(env, { rowId, dedupeKey, workspaceId: workspace_id });
        if ((reclaim.meta?.changes ?? 0) === 0) return { skipped: "duplicate" };
        // Reclaim itself proves the provider has not been invoked in this new
        // attempt; it may advance immediately to the separate admission CAS.
        allowImmediate = true;
      } else if (existing.status !== "pending" || existing.error !== LIFECYCLE_PROVIDER_NOT_STARTED) {
        return { skipped: "duplicate" };
      }
    }

    const origin = getEmailFrontendOrigin(env);
    const { subject, html, text } = buildLifecycleEmail(type, { origin, wsName: name, domain, scanQuality: scan_quality });
    const prepared = prepareEmailDelivery(subject, text, html, env, "HELLO_EMAIL_FROM", [email]);
    if (!prepared.ok) {
      await recordLifecyclePreflightFailure(env, { rowId, dedupeKey, workspaceId: workspace_id, reason: prepared.reason });
      emailDeliveryLog("error", { ...prepared.context, outcome: "skipped", reason: prepared.reason });
      return { sent: false, reason: prepared.reason };
    }

    let idempotencyKey;
    try {
      idempotencyKey = await lifecycleProviderIdempotencyKey(dedupeKey);
    } catch {
      await recordLifecyclePreflightFailure(env, { rowId, dedupeKey, workspaceId: workspace_id, reason: "idempotency_key_unavailable" });
      return { sent: false, reason: "idempotency_key_unavailable" };
    }

    // This expected-state CAS is the final D1 mutation before the provider. For
    // workspace-owned rows it also closes the soft-delete race atomically.
    const attempt = await claimLifecycleProviderAttempt(env, {
      rowId,
      dedupeKey,
      workspaceId: workspace_id,
      allowImmediate,
    });
    if ((attempt.meta?.changes ?? 0) === 0) return { skipped: "duplicate" };
    admitted = true;
    admittedRow = rowId;
    admittedDedupeKey = dedupeKey;

    // The guarded credential is deliberately read inside this helper, after the
    // CAS and immediately before fetch. A frozen A1 invocation therefore emits
    // no customer email even if the earlier deterministic preflight succeeded.
    const result = await deliverPreparedEmail(prepared, env, { idempotencyKey, lifecycleOutcomeContract: true });
    const terminal = await recordLifecycleProviderOutcome(env, { rowId, dedupeKey, workspaceId: workspace_id, result });
    if ((terminal.meta?.changes ?? 0) === 0) {
      return { sent: false, reason: "provider_outcome_unknown" };
    }
    return result.sent ? { sent: true } : { sent: false, reason: result.reason };
  } catch (e) {
    if (admitted && admittedRow && admittedDedupeKey) {
      try {
        await recordLifecycleProviderOutcome(env, {
          rowId: admittedRow,
          dedupeKey: admittedDedupeKey,
          workspaceId: workspace_id,
          result: { sent: false, reason: "provider_outcome_unknown", outcomeUnknown: true },
        });
      } catch { /* keep the admitted row conservatively in sending */ }
    }
    console.error("[lifecycle-email]", String(e?.message ?? e));
    return { sent: false, reason: "error" };
  }
}

/**
 * retryFailedLifecycleEmails — hourly cron sweep that re-sends lifecycle emails
 * whose first attempt FAILED. This decouples delivery from the context that
 * originally failed: e.g. lifecycle_first_scan_completed is sent at the end of
 * the subrequest-heavy scan engine (ctx.waitUntil), where the outbound Resend
 * fetch can fail; the cron runs in a clean, light invocation with full
 * subrequest budget. Re-firing sendLifecycleEmail reuses the retry-claim path,
 * so the same failed row is reclaimed and re-sent (never double-sent).
 *
 * Excludes lifecycle_payment_failed: its dedupe key includes the Stripe invoice
 * id (`ref`), which is not stored on the row, so it cannot be safely rebuilt
 * here — and it is sent from the light webhook context anyway. Bounded to a
 * 3-day window and 10 rows per run. Never throws.
 */
async function retryFailedLifecycleEmails(env) {
  try {
    const rows = await env.cybermeters_db
      .prepare(`SELECT le.id, le.type, le.user_id, le.workspace_id, le.domain,
                       CASE WHEN le.type = 'lifecycle_first_scan_completed' THEN (
                         SELECT s.scan_quality
                         FROM scans s
                         WHERE s.workspace_id = le.workspace_id
                           AND lower(s.domain) = lower(le.domain)
                           AND s.status = 'completed'
                         ORDER BY s.created_at ASC, s.id ASC
                         LIMIT 1
                       ) ELSE NULL END AS scan_quality
                FROM lifecycle_email_events le
                WHERE le.type != 'lifecycle_payment_failed'
                  AND le.type != 'lifecycle_weekly_digest'
                  AND le.created_at > datetime('now', '-3 days')
                  AND (
                    (le.status = 'pending'
                      AND le.error = 'provider_not_started'
                      AND le.created_at < datetime('now', '-15 minutes'))
                    OR (le.status = 'failed' AND (
                      le.error IN ('missing_api_key','invalid_sender','no_valid_recipients','invalid_content','idempotency_key_unavailable')
                      OR (le.error = 'provider_rejected' AND le.created_at < datetime('now', '-24 hours'))
                    ))
                  )
                ORDER BY le.created_at ASC
                LIMIT 10`)
      .all().catch(() => null);
    for (const row of (rows?.results || [])) {
      await sendLifecycleEmail(env, {
        type:         row.type,
        user_id:      row.user_id ?? null,
        workspace_id: row.workspace_id ?? null,
        domain:       row.domain ?? null,
        scan_quality: row.scan_quality ?? null,
        _recovery_id: row.id,
      }).catch(() => {});
    }
  } catch (e) {
    console.error("[lifecycle-retry]", String(e?.message ?? e));
  }
}

// corsHeaders is request-scoped — see buildCorsHeaders(env) below.
// The module-level fallback is used only outside the fetch handler (e.g. json() default).
function buildCorsHeaders(env) {
  return {
    "Access-Control-Allow-Origin":  (env && env.ALLOWED_ORIGIN) || "https://app.cybermeters.com",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Expose-Headers": "X-Request-ID",
  };
}

// Module-level json() uses the production default — overridden per-request inside fetch().
function buildJsonHeaders(_corsHeaders = buildCorsHeaders(null)) {
  return {
    ..._corsHeaders,
    // Prevent Cloudflare edge and browser caches from serving stale API responses.
    // Scan status, notifications, and workspace data change frequently and must
    // always reflect the current database state.
    'Cache-Control': 'no-store',
    // Defence-in-depth for a JSON API: none of these responses are documents,
    // but the headers cost nothing and close residual framing/sniffing paths.
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'",
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  };
}

function json(data, status = 200, _corsHeaders = buildCorsHeaders(null)) {
  return Response.json(normalizeApiResponseData(data, status), {
    status,
    headers: buildJsonHeaders(_corsHeaders),
  });
}

export {
  EMAIL_SENDER_KEYS,
  LIFECYCLE_TYPES,
  _lifecycleHtml,
  buildCorsHeaders,
  buildJsonHeaders,
  buildLifecycleEmail,
  deliverEmail,
  emailDeliveryLog,
  escapeEmailHtml,
  getEmailFrontendOrigin,
  json,
  lifecycleDedupeKey,
  normalizeEmailRecipients,
  resolveEmailSender,
  retryFailedLifecycleEmails,
  sendCustomerEmail,
  sendLifecycleEmail,
};
