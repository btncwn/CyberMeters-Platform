// ── Lifecycle email service ──────────────────────────────────────────────────
// Build/send/dedupe/retry for customer lifecycle email via Resend. Fail-open:
// a failed send is recorded and retried by the hourly cron, never thrown.
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

async function deliverEmail(subject, text, html, env, fromKey, toEmails) {
  const to = normalizeEmailRecipients(toEmails);
  const from = resolveEmailSender(env, fromKey);
  const safeSubject = String(subject || "").replace(/[\r\n]+/g, " ").trim();
  const context = { from_key: fromKey, recipient_count: to.length };

  if (!env.RESEND_API_KEY) {
    emailDeliveryLog("error", { ...context, outcome: "skipped", reason: "missing_api_key" });
    return { sent: false, reason: "missing_api_key" };
  }
  if (!from) {
    emailDeliveryLog("error", { ...context, outcome: "skipped", reason: "invalid_sender" });
    return { sent: false, reason: "invalid_sender" };
  }
  if (to.length === 0) {
    emailDeliveryLog("error", { ...context, outcome: "skipped", reason: "no_valid_recipients" });
    return { sent: false, reason: "no_valid_recipients" };
  }
  if (!safeSubject || !String(text || "").trim() || !String(html || "").trim()) {
    emailDeliveryLog("error", { ...context, outcome: "skipped", reason: "invalid_content" });
    return { sent: false, reason: "invalid_content" };
  }

  try {
    const response = await fetch("https://api.resend.com/emails", {
      method:  "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
      },
      body: JSON.stringify({ from, to, subject: safeSubject, text, html }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) {
      emailDeliveryLog("error", { ...context, outcome: "failed", reason: "provider_rejected", status: response.status });
      return { sent: false, reason: "provider_rejected", status: response.status };
    }
    let providerId = null;
    try { providerId = (await response.json())?.id || null; } catch { /* response ID is optional */ }
    emailDeliveryLog("info", { ...context, outcome: "accepted", provider_id: providerId });
    return { sent: true, provider_id: providerId };
  } catch (error) {
    emailDeliveryLog("error", {
      ...context,
      outcome: "failed",
      reason: error?.name === "TimeoutError" ? "timeout" : "network_error",
    });
    return { sent: false, reason: error?.name === "TimeoutError" ? "timeout" : "network_error" };
  }
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
function buildLifecycleEmail(type, { origin = null, wsName = null, domain = null } = {}) {
  const link = (path) => (origin ? `${origin}${path}` : null);
  const ws = wsName ? escapeEmailHtml(wsName) : "your workspace";
  const dom = domain ? escapeEmailHtml(domain) : "your domain";
  const SERVICES_LINE = "Email Protection (DMARC &amp; impersonation), Brand Protection (lookalike domains), Attack Surface (exposed assets) and Certificates &amp; Trust (TLS &amp; expiry).";

  let subject, heading, paras, ctaLabel, ctaPath;
  switch (type) {
    case "lifecycle_welcome":
      subject = "Welcome to CyberMeters";
      heading = "Welcome to CyberMeters";
      paras = [
        "CyberMeters protects your email, brand, external attack surface and certificates from one workspace.",
        `Four services work together: ${SERVICES_LINE}`,
        "To get started, add a domain and run your first scan.",
      ];
      ctaLabel = "Open CyberMeters"; ctaPath = "/services";
      break;
    case "lifecycle_workspace_created":
      subject = "Your CyberMeters workspace is ready";
      heading = "Your workspace is ready";
      paras = [
        `Your workspace (${ws}) is set up.`,
        `A workspace connects ${SERVICES_LINE}`,
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
    case "lifecycle_first_scan_completed":
      subject = "Your first CyberMeters scan is complete";
      heading = "Your first scan is complete";
      paras = [
        `Your first scan for ${dom} has finished.`,
        "Review your results: findings are issues worth acting on, while observations are informational signals about your external footprint.",
      ];
      ctaLabel = "Review your dashboard"; ctaPath = "/dashboard";
      break;
    case "lifecycle_payment_failed":
      subject = "Action needed: your CyberMeters payment could not be processed";
      heading = "Your payment could not be processed";
      paras = [
        "The latest payment for your CyberMeters subscription could not be processed.",
        "Please update your payment method to keep your paid plan active. The charge will be retried automatically over the next few days.",
        "If payment continues to fail, your account will move to the free plan. Your data and settings are kept safe either way.",
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
async function sendLifecycleEmail(env, { type, user_id = null, workspace_id = null, domain = null, to = null, wsName = null, ref = null } = {}) {
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
      const row = await env.cybermeters_db
        .prepare("SELECT u.id AS uid, u.email AS email, u.email_verified AS ev, w.name AS wname FROM workspaces w JOIN users u ON u.id = w.owner_user_id WHERE w.id = ? LIMIT 1")
        .bind(workspace_id).first();
      if (row?.ev && isValidEmail(String(row.email || "").toLowerCase())) email = String(row.email).toLowerCase();
      uid = uid ?? row?.uid ?? null;
      if (!name) name = row?.wname || null;
    }
    if (!email) return { skipped: "no_verified_email" };

    const dedupeKey = lifecycleDedupeKey({ type, user_id: uid, workspace_id, domain, ref });
    let rowId = createId("lifemail");
    const ins = await env.cybermeters_db
      .prepare(`INSERT INTO lifecycle_email_events (id, user_id, workspace_id, domain, type, dedupe_key, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', datetime('now'))
                ON CONFLICT(dedupe_key) DO NOTHING`)
      .bind(rowId, uid ?? null, workspace_id ?? null, domain ?? null, type, dedupeKey)
      .run();

    // Conflict → a row for this scope already exists. Retry only if the prior
    // attempt FAILED (e.g. a transient network error); 'sent' and in-flight
    // 'pending' rows are still deduped so we never double-send. Claiming the
    // failed row back to 'pending' also guards against two concurrent retries.
    if ((ins.meta?.changes ?? 0) === 0) {
      const existing = await env.cybermeters_db
        .prepare("SELECT id, status FROM lifecycle_email_events WHERE dedupe_key = ? LIMIT 1")
        .bind(dedupeKey).first();
      if (!existing || existing.status !== "failed") return { skipped: "duplicate" };
      const claim = await env.cybermeters_db
        .prepare("UPDATE lifecycle_email_events SET status = 'pending', error = NULL WHERE id = ? AND status = 'failed'")
        .bind(existing.id).run();
      if ((claim.meta?.changes ?? 0) === 0) return { skipped: "duplicate" };
      rowId = existing.id;
    }

    const origin = getEmailFrontendOrigin(env);
    const { subject, html, text } = buildLifecycleEmail(type, { origin, wsName: name, domain });
    const res = await sendCustomerEmail(subject, text, html, env, "HELLO_EMAIL_FROM", [email]);

    await env.cybermeters_db
      .prepare(`UPDATE lifecycle_email_events
                SET status = ?, provider_id = ?, error = ?, sent_at = CASE WHEN ? = 'sent' THEN datetime('now') ELSE sent_at END
                WHERE id = ?`)
      .bind(res.sent ? "sent" : "failed", res.provider_id || null, res.sent ? null : (res.reason || "send_failed"), res.sent ? "sent" : "failed", rowId)
      .run();
    return res.sent ? { sent: true } : { sent: false, reason: res.reason };
  } catch (e) {
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
      .prepare(`SELECT id, type, user_id, workspace_id, domain
                FROM lifecycle_email_events
                WHERE status = 'failed'
                  AND type != 'lifecycle_payment_failed'
                  AND created_at > datetime('now', '-3 days')
                ORDER BY created_at ASC
                LIMIT 10`)
      .all().catch(() => null);
    for (const row of (rows?.results || [])) {
      await sendLifecycleEmail(env, {
        type:         row.type,
        user_id:      row.user_id ?? null,
        workspace_id: row.workspace_id ?? null,
        domain:       row.domain ?? null,
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
