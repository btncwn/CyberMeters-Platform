// ── Public free tools: /api/tools/* ─────────────────────────────────────────
//
//   GET  /api/tools/config            Turnstile site key and the public limits
//   POST /api/tools/:tool/check       run one check (dmarc | spf | headers | lookalike)
//   POST /api/tools/:tool/defer       leave an email while the daily budget is used up
//   POST /api/tools/share             check a shared result link
//
// Every check passes the shared gate in lib/free-tool-gate.js (input →
// Turnstile → limiter read → cache → limiter claim → lookup). The DMARC, SPF and
// lookalike tools ask DNS questions through the existing DoH helpers, nothing
// else; the
// headers tool makes one GET of the home page through the SSRF-guarded
// safeFetch (every hop re-resolved, private and reserved addresses refused).
import { sendAlertEmail } from "../engines/alerts.js";
import { dnsQuery } from "../engines/dns.js";
import { runDmarcCheck } from "../engines/free-tools/dmarc-check.js";
import { runHeadersCheck } from "../engines/free-tools/headers-check.js";
import { runLookalikeCheck } from "../engines/free-tools/lookalike-check.js";
import { runSpfCheck } from "../engines/free-tools/spf-check.js";
import { makeDnsCache, PhysicalSubrequestCounter } from "../engines/scan-budget.js";
import {
  defaultToolCache, domainCapKey, FREE_TOOL_IDS, FREE_TOOL_POLICY,
  normaliseToolDomain, readToolCache, verifyTurnstile, writeToolCache,
} from "../lib/free-tool-gate.js";
import { MAX_SHARE_TOKEN_CHARS, signShareToken, verifyShareToken } from "../lib/free-tool-share.js";
import { escapeEmailHtml, sendCustomerEmail } from "../lib/lifecycle-email.js";
import { createId, isValidEmail } from "../lib/util.js";

const MARKETING_ORIGIN = "https://cybermeters.com";

export const FREE_TOOLS = Object.freeze({
  dmarc: { name: "DMARC", path: "/tools/dmarc-checker" },
  spf: { name: "SPF", path: "/tools/spf-checker" },
  headers: { name: "security headers", path: "/tools/security-headers-checker" },
  lookalike: { name: "lookalike domain", path: "/tools/lookalike-domain-checker" },
});

const DEFAULT_RUNNERS = Object.freeze({
  dmarc: (domain, { accounting, signal, cache }) => runDmarcCheck(domain, { accounting, signal, cache }),
  spf: (domain, { accounting, signal, cache }) => runSpfCheck(domain, {
    dnsQuery: (name, type) => dnsQuery(name, type, { accounting, signal, cache }),
  }),
  headers: (domain, { accounting, signal, cache }) => runHeadersCheck(domain, { accounting, signal, cache, dnsQuery }),
  lookalike: (domain, { accounting, signal, cache }) => runLookalikeCheck(domain, {
    registrable: domainCapKey(domain),
    dnsQuery: (name, type) => dnsQuery(name, type, { accounting, signal, cache }),
  }),
});

const MESSAGES = Object.freeze({
  verification_required: "Please complete the quick human check, then run the check again.",
  verification_failed: "The human check did not pass. Please try it again.",
  verification_unavailable: "Free checks are briefly unavailable. Please try again in a few minutes.",
  limiter_unavailable: "Free checks are briefly unavailable. Please try again in a few minutes.",
  limit_ip: "You have used today's free checks for this tool from this connection.",
  limit_user: "You have reached today's limit for this tool on your account.",
  limit_domain: "This domain has been checked many times in the last hour.",
  capacity: "Free checks are very busy today. Leave your email and we will send this result as soon as capacity returns.",
});

async function readBody(request, json, maxBytes = FREE_TOOL_POLICY.maxBodyBytes) {
  const declared = Number(request.headers.get("Content-Length") || 0);
  if (declared > maxBytes) return { error: json({ status: "invalid_input", code: "body_too_large", message: "Request too large." }, 413) };
  const text = await request.text().catch(() => null);
  if (text == null || text.length > maxBytes) return { error: json({ status: "invalid_input", code: "body_too_large", message: "Request too large." }, 413) };
  try {
    const body = JSON.parse(text);
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("not an object");
    return { body };
  } catch {
    return { error: json({ status: "invalid_input", code: "invalid_json", message: "Request could not be read." }, 400) };
  }
}

// A signed-in user with at least one live workspace. Anything else, including
// a bad token, is treated as an anonymous visitor (and so needs Turnstile).
async function signedInWorkspaceUser(rctx) {
  const { request, env, requireAuth } = rctx;
  if (!(request.headers.get("Authorization") || "").startsWith("Bearer ")) return null;
  try {
    const user = await requireAuth(request, env);
    if (!user?.id) return null;
    const membership = await env.cybermeters_db.prepare(
      `SELECT 1 AS ok FROM workspace_members wm
       JOIN workspaces w ON w.id = wm.workspace_id
       WHERE wm.user_id = ? AND w.deleted_at IS NULL LIMIT 1`,
    ).bind(user.id).first();
    return membership ? user : null;
  } catch {
    return null;
  }
}

function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

function limitResponse(json, env, scope, limited) {
  return json({
    status: "limit_reached",
    scope,
    reset_at: limited?.body?.reset_at ?? null,
    message: MESSAGES[`limit_${scope}`],
    trial_url: `${env.FRONTEND_URL || "https://app.cybermeters.com"}/signup`,
  }, 429);
}

function capacityResponse(json, limited) {
  return json({ status: "capacity_paused", can_defer: true, reset_at: limited?.body?.reset_at ?? null, message: MESSAGES.capacity }, 429);
}

function unavailable(json, code) {
  return json({ status: "unavailable", code, message: MESSAGES[code] }, 503);
}

// The limiter answers null (allowed), 429 (full) or 503 (could not answer).
// 503 refuses: a limiter that cannot count never means "unlimited".
function limiterRefusal(json, env, scope, limited) {
  if (!limited) return null;
  if (limited.status !== 429) return unavailable(json, "limiter_unavailable");
  return scope === "global" ? capacityResponse(json, limited) : limitResponse(json, env, scope, limited);
}

async function limitScopes(rctx, tool, domain, user) {
  const { request, rateLimitScopeId } = rctx;
  const P = FREE_TOOL_POLICY;
  return [
    user
      ? { scope: "user", action: `free_tool_user_${tool}`, limit: P.userRuns, window: P.userWindowSeconds, rolling: false,
        key: { scope: "user", scope_id: await rateLimitScopeId(`freetool-user-${tool}`, user.id) } }
      : { scope: "ip", action: `free_tool_ip_${tool}`, limit: P.ipRuns, window: P.ipWindowSeconds, rolling: true,
        key: { scope: "ip", scope_id: await rateLimitScopeId(`freetool-ip-${tool}`, clientIp(request)) } },
    { scope: "domain", action: `free_tool_domain_${tool}`, limit: P.domainRuns, window: P.domainWindowSeconds, rolling: false,
      key: { scope: "domain", scope_id: await rateLimitScopeId(`freetool-domain-${tool}`, domainCapKey(domain)) } },
    { scope: "global", action: "free_tool_global", limit: P.dailyBudget, window: P.budgetWindowSeconds, rolling: false,
      key: { scope: "global", scope_id: "free_tool_global" } },
  ];
}

async function checkLimits(rctx, scopes, { peek, onGlobalCount = null }) {
  const { env, json, consumeApiRateLimit } = rctx;
  for (const limit of scopes) {
    const limited = await consumeApiRateLimit(env, [limit.key], limit.action, limit.limit, limit.window, {
      failClosed: true,
      atomic: true,
      rolling: limit.rolling,
      peek,
      ...(limit.scope === "global" && onGlobalCount ? { onCount: onGlobalCount } : {}),
    });
    const refusal = limiterRefusal(json, env, limit.scope, limited);
    if (refusal) return refusal;
  }
  return null;
}

// Tell the founder once at each threshold of the daily budget. The atomic
// counter hands each count to exactly one request, so each mail goes once a day.
function budgetWatcher(env, ctx, sendAlert = sendAlertEmail) {
  const P = FREE_TOOL_POLICY;
  const thresholds = new Map(P.alertFractions.map((fraction) => [Math.ceil(P.dailyBudget * fraction), `${Math.round(fraction * 100)}%`]));
  thresholds.set(P.dailyBudget + 1, "100% — the breaker has tripped");
  return (count) => {
    const label = thresholds.get(count);
    if (!label) return;
    const text = [
      `The free tools have used ${label} of today's budget (${Math.min(count, P.dailyBudget)} of ${P.dailyBudget} checks, UTC day).`,
      "",
      count > P.dailyBudget
        ? "New checks now offer to email the result later; deferred checks run hourly once the budget resets at 00:00 UTC."
        : "Nothing has been refused yet. If this is not real demand, look for one source sending many checks.",
    ].join("\n");
    const send = Promise.resolve().then(() => sendAlert(`[CyberMeters] Free tools budget at ${label}`, text, `<p>${escapeEmailHtml(text).replace(/\n/g, "<br>")}</p>`, env))
      .catch(() => null);
    if (ctx?.waitUntil) ctx.waitUntil(send);
  };
}

async function runTool(rctx, tool, domain) {
  const runners = { ...DEFAULT_RUNNERS, ...(rctx.freeToolRunners || {}) };
  const counter = new PhysicalSubrequestCounter({ limit: FREE_TOOL_POLICY.subrequestLimit, safetyMargin: 0 });
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort("free_tool_deadline"), FREE_TOOL_POLICY.deadlineMs);
  try {
    return await runners[tool](domain, {
      accounting: counter.contextFor(`free_tool_${tool}`, { signal: deadline.signal }),
      signal: deadline.signal,
      cache: makeDnsCache(),
    });
  } finally {
    clearTimeout(timer);
  }
}

async function withShare(env, result) {
  const share = await signShareToken(env, result).catch(() => null);
  const tool = FREE_TOOLS[result?.tool];
  return share && tool
    ? { token: share.token, expires_at: share.expires_at, url: `${MARKETING_ORIGIN}${tool.path}#share=${share.token}` }
    : null;
}

async function handleCheck(rctx, tool) {
  const { request, env, ctx, json } = rctx;
  const parsed = await readBody(request, json);
  if (parsed.error) return parsed.error;
  const input = normaliseToolDomain(parsed.body.domain);
  if (!input.ok) return json({ status: "invalid_input", code: input.code, message: input.message }, 400);
  const { domain } = input;

  const user = await signedInWorkspaceUser(rctx);
  if (!user) {
    const verified = await verifyTurnstile(env, parsed.body.turnstile_token, {
      remoteIp: request.headers.get("CF-Connecting-IP"),
      action: `tool_${tool}`,
      fetchImpl: rctx.turnstileFetch || fetch,
    });
    if (!verified.ok) return json({ status: verified.code, code: verified.code, message: MESSAGES[verified.code] }, verified.status);
  }

  const scopes = await limitScopes(rctx, tool, domain, user);
  const early = await checkLimits(rctx, scopes, { peek: true });
  if (early) return early;

  const cache = rctx.freeToolCache === undefined ? defaultToolCache() : rctx.freeToolCache;
  const cached = await readToolCache(cache, tool, domain);
  if (cached) return json({ status: "ok", tool, cached: true, result: cached, share: await withShare(env, cached) });

  const refused = await checkLimits(rctx, scopes, { peek: false, onGlobalCount: budgetWatcher(env, ctx, rctx.freeToolAlert) });
  if (refused) return refused;

  let result;
  try {
    result = await runTool(rctx, tool, domain);
  } catch {
    return json({ status: "unavailable", code: "lookup_failed", message: "The check could not finish. Nothing was concluded about this domain; please try again." }, 503);
  }
  // Only a conclusive result is cached; a failed lookup is retried next time.
  if (result?.verdict?.level !== "unknown") await writeToolCache(cache, tool, domain, result);
  return json({ status: "ok", tool, cached: false, result, share: await withShare(env, result) });
}

async function handleDefer(rctx, tool) {
  const { request, env, json, consumeApiRateLimit, rateLimitScopeId } = rctx;
  const P = FREE_TOOL_POLICY;
  const parsed = await readBody(request, json);
  if (parsed.error) return parsed.error;
  const input = normaliseToolDomain(parsed.body.domain);
  if (!input.ok) return json({ status: "invalid_input", code: input.code, message: input.message }, 400);
  const email = typeof parsed.body.email === "string" ? parsed.body.email.trim().toLowerCase() : "";
  if (!isValidEmail(email)) return json({ status: "invalid_input", code: "invalid_email", message: "Enter an email address we can send the result to." }, 400);
  if (parsed.body.consent !== true) return json({ status: "invalid_input", code: "consent_required", message: "Please confirm we may email you this one result." }, 400);

  const user = await signedInWorkspaceUser(rctx);
  if (!user) {
    const verified = await verifyTurnstile(env, parsed.body.turnstile_token, {
      remoteIp: request.headers.get("CF-Connecting-IP"),
      action: `tool_${tool}_defer`,
      fetchImpl: rctx.turnstileFetch || fetch,
    });
    if (!verified.ok) return json({ status: verified.code, code: verified.code, message: MESSAGES[verified.code] }, verified.status);
  }
  const limited = await consumeApiRateLimit(env,
    [{ scope: "ip", scope_id: await rateLimitScopeId("freetool-defer", clientIp(request)) }],
    "free_tool_defer_ip", P.deferIpRuns, P.ipWindowSeconds, { failClosed: true, atomic: true, rolling: true });
  const refusal = limiterRefusal(json, env, "ip", limited);
  if (refusal) return refusal;

  try {
    const pending = await env.cybermeters_db.prepare("SELECT COUNT(*) AS n FROM free_tool_deferred_checks").bind().first();
    if ((pending?.n ?? P.deferPendingMax) >= P.deferPendingMax) {
      return json({ status: "queue_full", message: "We cannot take more requests today. Please try the check again tomorrow." }, 429);
    }
    const now = new Date().toISOString();
    await env.cybermeters_db.prepare(
      `INSERT INTO free_tool_deferred_checks (id, tool, domain, email, consent_at, created_at, attempts)
       VALUES (?, ?, ?, ?, ?, ?, 0)
       ON CONFLICT(tool, domain, email) DO NOTHING`,
    ).bind(createId("ftd"), tool, input.domain, email, now, now).run();
  } catch {
    return unavailable(json, "limiter_unavailable");
  }
  return json({
    status: "queued",
    message: `We will email the ${FREE_TOOLS[tool].name} result for ${input.domain} to ${email} as soon as capacity returns, usually within a day. The address is used only for this result and deleted once it is sent.`,
  });
}

export function isFreeToolPath(pathname) {
  return String(pathname).startsWith("/api/tools/");
}

export async function freeToolsRoutes(rctx) {
  const { request, env, url, json } = rctx;
  if (!isFreeToolPath(url.pathname)) return null;

  if (url.pathname === "/api/tools/config" && request.method === "GET") {
    const siteKey = typeof env.TURNSTILE_SITE_KEY === "string" ? env.TURNSTILE_SITE_KEY.trim() : "";
    return json({
      available: Boolean(siteKey && env.TURNSTILE_SECRET_KEY),
      turnstile_site_key: siteKey || null,
      tools: FREE_TOOL_IDS.map((id) => ({ id, name: FREE_TOOLS[id].name, path: FREE_TOOLS[id].path })),
      limits: { runs_per_tool_per_day: FREE_TOOL_POLICY.ipRuns, cache_minutes: FREE_TOOL_POLICY.cacheSeconds / 60 },
    });
  }

  if (url.pathname === "/api/tools/share" && request.method === "POST") {
    const parsed = await readBody(request, json, MAX_SHARE_TOKEN_CHARS + 256);
    if (parsed.error) return parsed.error;
    const token = parsed.body.token;
    if (typeof token !== "string" || token.length > MAX_SHARE_TOKEN_CHARS) return json({ status: "invalid_link" }, 400);
    const verified = await verifyShareToken(env, token);
    if (!verified.ok) return json({ status: verified.code }, verified.code === "sharing_unavailable" ? 503 : 400);
    return json({ status: "ok", result: verified.result, expires_at: verified.expires_at });
  }

  const match = url.pathname.match(/^\/api\/tools\/([a-z]+)\/(check|defer)$/);
  if (match && request.method === "POST" && FREE_TOOL_IDS.includes(match[1])) {
    return match[2] === "check" ? handleCheck(rctx, match[1]) : handleDefer(rctx, match[1]);
  }
  return json({ error: "Not found" }, 404);
}

// ── Deferred results (hourly cron) ──────────────────────────────────────────

function resultEmail(tool, result, share) {
  const toolInfo = FREE_TOOLS[tool];
  const link = share?.url || `${MARKETING_ORIGIN}${toolInfo.path}`;
  const record = result?.next_step?.record;
  const lines = [
    `Your ${toolInfo.name} check for ${result.domain}`,
    "",
    result.verdict?.headline || "",
    result.verdict?.summary || "",
    "",
    `Next step: ${result.next_step?.title || ""}`,
    result.next_step?.explanation || "",
    ...(record ? ["", `${record.type} record at ${record.name}:`, record.value] : []),
    ...(Array.isArray(result?.next_step?.headers) && result.next_step.headers.length
      ? ["", "Headers to add:", ...result.next_step.headers.map((h) => `${h.name}: ${h.value}`)] : []),
    "",
    `Full result${share ? " (link valid for 7 days)" : ""}: ${link}`,
    "",
    "You asked for this one result when the free checks were busy. Your address has now been deleted.",
  ];
  const text = lines.join("\n");
  const html = `<div style="font-family:system-ui,sans-serif;line-height:1.5">${lines
    .map((line) => (line ? `<p style="margin:0 0 8px">${escapeEmailHtml(line)}</p>` : ""))
    .join("")}</div>`;
  return { subject: `Your ${toolInfo.name} result for ${result.domain}`, text, html };
}

export async function processFreeToolDeferredChecks(env, deps = {}) {
  const P = FREE_TOOL_POLICY;
  const db = env.cybermeters_db;
  const nowMs = deps.now ?? Date.now();
  const expiry = new Date(nowMs - P.deferMaxAgeHours * 3600 * 1000).toISOString();
  await db.prepare("DELETE FROM free_tool_deferred_checks WHERE created_at < ? OR attempts >= ?")
    .bind(expiry, P.deferMaxAttempts).run();

  const { consumeApiRateLimit } = deps;
  const budget = { scope: "global", scope_id: "free_tool_global" };
  const paused = await consumeApiRateLimit(env, [budget], "free_tool_global", P.dailyBudget, P.budgetWindowSeconds, { failClosed: true, atomic: true, peek: true });
  if (paused) return { status: paused.status === 429 ? "paused" : "limiter_unavailable", sent: 0 };

  const { results = [] } = await db.prepare(
    "SELECT id, tool, domain, email, attempts FROM free_tool_deferred_checks ORDER BY created_at ASC LIMIT ?",
  ).bind(P.deferBatch).all();
  let sent = 0;
  for (const row of results) {
    if (!FREE_TOOL_IDS.includes(row.tool)) {
      await db.prepare("DELETE FROM free_tool_deferred_checks WHERE id = ?").bind(row.id).run();
      continue;
    }
    const claimed = await consumeApiRateLimit(env, [budget], "free_tool_global", P.dailyBudget, P.budgetWindowSeconds, { failClosed: true, atomic: true });
    if (claimed) break;
    let delivered = false;
    try {
      const result = await runTool({ freeToolRunners: deps.freeToolRunners }, row.tool, row.domain);
      const mail = resultEmail(row.tool, result, await withShare(env, result));
      const outcome = await (deps.sendEmail || sendCustomerEmail)(mail.subject, mail.text, mail.html, env, "HELLO_EMAIL_FROM", [row.email]);
      delivered = outcome?.sent === true;
    } catch {
      delivered = false;
    }
    if (delivered) {
      await db.prepare("DELETE FROM free_tool_deferred_checks WHERE id = ?").bind(row.id).run();
      sent += 1;
    } else {
      await db.prepare("UPDATE free_tool_deferred_checks SET attempts = attempts + 1, last_attempt_at = ? WHERE id = ?")
        .bind(new Date(nowMs).toISOString(), row.id).run();
    }
  }
  return { status: "ok", sent };
}
