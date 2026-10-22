// ── Browser error reports and the "Something wrong?" button ─────────────────
//
//   POST /api/client-errors   counted, never stored as text
//   POST /api/feedback        stored for 90 days, read in the founder's email
//
// Both are anonymous (no Authorization read), accept only fixed fields, keep
// no IP (rate limits use hashed keys) and refuse when the limiter cannot
// answer. Shared contract with the frontend: see docs in the PR that added it.
import { bumpDailyCounter, routeFamily, safeCode } from "../lib/ops-counters.js";
import { createId, isValidEmail } from "../lib/util.js";
import { sendAlertEmail } from "../engines/alerts.js";
import { escapeEmailHtml } from "../lib/lifecycle-email.js";

export const FEEDBACK_LIMITS = Object.freeze({
  maxBodyBytes: 4096, messageMax: 2000, pathMax: 200, buildMax: 64,
  perIpPerHour: 5, globalPerDay: 200, retentionDays: 90, replyEmailMax: 254,
  // Immediate founder email per accepted report (S2-FEEDBACK-NOW). Per source it
  // is bounded by perIpPerHour above (the form is anonymous: there is no
  // workspace to count by); beyond the global cap a report is stored for the
  // daily digest only.
  emailsPerHour: 30,
});
export const CLIENT_ERROR_LIMITS = Object.freeze({
  maxBodyBytes: 2048, perIpPerHour: 30, globalPerDay: 5000,
});

const SURFACES = new Set(["free_scan", "free_tool", "app"]);
const ERROR_KINDS = new Set(["js_error", "unhandled_rejection", "chunk_load", "api_error", "render_error"]);
const TOOL = /^[a-z0-9-]{1,40}$/;
const BUILD = /^(dev|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
// Path segments that look like a secret: invitation tokens and long opaque values.
const SECRET_SEGMENT = /^(cmi_[A-Za-z0-9_-]+|[A-Fa-f0-9]{32,}|[A-Za-z0-9_-]{32,})$/;

export function isOpsIntakePath(pathname) {
  return pathname === "/api/feedback" || pathname === "/api/client-errors";
}

async function readJson(request, maxBytes) {
  if (request.headers.get("Content-Type")?.split(";")[0].trim() !== "application/json") return { error: "content_type" };
  if (Number(request.headers.get("Content-Length") || 0) > maxBytes) return { error: "too_large" };
  const text = await request.text().catch(() => null);
  if (text == null || text.length > maxBytes) return { error: "too_large" };
  try {
    const body = JSON.parse(text);
    return body && typeof body === "object" && !Array.isArray(body) ? { body } : { error: "not_object" };
  } catch {
    return { error: "invalid_json" };
  }
}

/** A path as stored: starts with "/", no query or fragment, secret-looking segments redacted. */
export function cleanPath(path, max = FEEDBACK_LIMITS.pathMax) {
  if (typeof path !== "string" || !path.startsWith("/") || path.length > max || /[?#\s\\]/.test(path)) return null;
  return path.split("/").map((segment) => (SECRET_SEGMENT.test(segment) ? ":redacted" : segment)).join("/");
}

function onlyKeys(body, allowed) {
  return Object.keys(body).every((key) => allowed.includes(key));
}

async function limited(rctx, action, perIp, perDay) {
  const { request, env, consumeApiRateLimit, rateLimitScopeId } = rctx;
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const ipLimit = await consumeApiRateLimit(env, [{ scope: "ip", scope_id: await rateLimitScopeId(action, ip) }],
    `${action}_ip`, perIp, 3600, { failClosed: true, atomic: true, saturating: true });
  if (ipLimit) return ipLimit;
  return consumeApiRateLimit(env, [{ scope: "global", scope_id: action }],
    `${action}_global`, perDay, 86400, { failClosed: true, atomic: true, saturating: true });
}

export function validateFeedback(body) {
  const keys = ["message", "surface", "tool", "path", "build", "error_code", "turnstile_token", "reply_email"];
  if (!onlyKeys(body, keys)) return null;
  const message = typeof body.message === "string" ? body.message.trim() : "";
  if (message.length < 1 || message.length > FEEDBACK_LIMITS.messageMax) return null;
  if (!SURFACES.has(body.surface)) return null;
  const tool = body.tool ?? null;
  if (body.surface === "free_tool" ? !(typeof tool === "string" && TOOL.test(tool)) : tool !== null) return null;
  const path = cleanPath(body.path);
  if (!path) return null;
  if (typeof body.build !== "string" || body.build.length > FEEDBACK_LIMITS.buildMax || !BUILD.test(body.build)) return null;
  const errorCode = body.error_code ?? null;
  if (errorCode !== null && !(typeof errorCode === "string" && /^[a-z0-9_.-]{1,64}$/.test(errorCode))) return null;
  // Optional, never required: an address the sender chose to give for a reply.
  let replyEmail = null;
  if (body.reply_email != null && body.reply_email !== "") {
    if (typeof body.reply_email !== "string") return null;
    const candidate = body.reply_email.trim();
    if (candidate) {
      if (candidate.length > FEEDBACK_LIMITS.replyEmailMax || !isValidEmail(candidate)) return null;
      replyEmail = candidate;
    }
  }
  return { message, surface: body.surface, tool, path, build: body.build.toLowerCase(), error_code: errorCode, reply_email: replyEmail };
}

export function validateClientError(body) {
  if (!onlyKeys(body, ["kind", "code", "path", "build", "status"])) return null;
  if (!ERROR_KINDS.has(body.kind)) return null;
  const path = cleanPath(body.path);
  if (!path) return null;
  if (typeof body.build !== "string" || !BUILD.test(body.build)) return null;
  const code = body.code == null ? "none" : safeCode(body.code);
  if (!code) return null;
  const status = body.status == null ? null : Number(body.status);
  if (status !== null && !(Number.isInteger(status) && status >= 100 && status <= 599)) return null;
  return { kind: body.kind, code, family: routeFamily(path), build: body.build.toLowerCase().slice(0, 8), status };
}

export function formatFeedbackEmail(feedback) {
  const lines = [
    `Where: ${feedback.surface}${feedback.tool ? ` · ${feedback.tool}` : ""} · ${feedback.path}`,
    `Build: ${feedback.build}${feedback.error_code ? ` · error ${feedback.error_code}` : ""}`,
    `Reply to: ${feedback.reply_email || "not given"}`,
    "",
    feedback.message,
  ];
  const text = lines.join("\n");
  return {
    subject: `CyberMeters feedback (${feedback.surface}${feedback.tool ? `: ${feedback.tool}` : ""})`,
    text,
    html: `<pre style="font-family:ui-monospace,monospace;font-size:13px;white-space:pre-wrap">${escapeEmailHtml(text)}</pre>`,
  };
}

// One email to the ops address per accepted report, bounded globally per hour.
// Over the cap, or when the limiter cannot answer, the report stays stored for
// the daily digest only. Returns { sent, reason }.
export async function notifyFounderOfFeedback(rctx, feedback) {
  const { env, consumeApiRateLimit } = rctx;
  const capped = await consumeApiRateLimit(env, [{ scope: "global", scope_id: "feedback_email" }],
    "feedback_email_global", FEEDBACK_LIMITS.emailsPerHour, 3600, { failClosed: true, atomic: true, saturating: true });
  if (capped) return { sent: false, reason: "digest_only" };
  const mail = formatFeedbackEmail(feedback);
  const result = await sendAlertEmail(mail.subject, mail.text, mail.html, env, "ALERT_EMAIL_FROM");
  return { sent: Boolean(result?.sent), reason: result?.sent ? null : (result?.reason || "not_sent") };
}

export async function opsIntakeRoutes(rctx) {
  const { request, env, url, json } = rctx;
  if (!isOpsIntakePath(url.pathname)) return null;
  if (request.method !== "POST") return json({ error: "Method not allowed", code: "method_not_allowed" }, 405);

  if (url.pathname === "/api/feedback") {
    const read = await readJson(request, FEEDBACK_LIMITS.maxBodyBytes);
    const feedback = read.body ? validateFeedback(read.body) : null;
    if (!feedback) return json({ error: "That message could not be sent.", code: "invalid_feedback" }, 400);
    const refused = await limited(rctx, "feedback", FEEDBACK_LIMITS.perIpPerHour, FEEDBACK_LIMITS.globalPerDay);
    if (refused) {
      return refused.status === 429
        ? json({ error: "Too many messages. Please try again later.", code: "rate_limited" }, 429)
        : json({ error: "Feedback is unavailable right now.", code: "feedback_unavailable" }, 503);
    }
    try {
      await env.cybermeters_db.prepare(
        `INSERT INTO feedback_reports (id, created_at, surface, tool, path, build, error_code, message, reply_email)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(createId("fb"), new Date().toISOString(), feedback.surface, feedback.tool, feedback.path,
        feedback.build, feedback.error_code, feedback.message, feedback.reply_email).run();
    } catch {
      return json({ error: "Feedback is unavailable right now.", code: "feedback_unavailable" }, 503);
    }
    // Stored first; the founder hears about it now, not only in the 09:00 digest.
    // Never delays or fails the customer's answer.
    const notify = notifyFounderOfFeedback(rctx, feedback).catch(() => ({ sent: false }));
    if (rctx.ctx?.waitUntil) rctx.ctx.waitUntil(notify); else await notify;
    return json({ ok: true }, 202);
  }

  const read = await readJson(request, CLIENT_ERROR_LIMITS.maxBodyBytes);
  const report = read.body ? validateClientError(read.body) : null;
  if (!report) return json({ error: "Invalid report.", code: "invalid_client_error" }, 400);
  const refused = await limited(rctx, "client_error", CLIENT_ERROR_LIMITS.perIpPerHour, CLIENT_ERROR_LIMITS.globalPerDay);
  if (refused) {
    return refused.status === 429
      ? json({ error: "Too many reports.", code: "rate_limited" }, 429)
      : json({ error: "Reporting is unavailable right now.", code: "client_errors_unavailable" }, 503);
  }
  const label = `${report.kind}|${report.code}|${report.status ?? "-"}|${report.family}|${report.build}`.slice(0, 200);
  await bumpDailyCounter(env, "client_error", label);
  return json({ ok: true }, 202);
}
