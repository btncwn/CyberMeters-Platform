// ── RUA ingestion + DMARC route management ──
// DMARC aggregate-report ingestion endpoints, sender intelligence (risk/readiness/summary +
// serialization), signed ingest tokens, DMARC-route status model, Cloudflare Email Routing
// exact-address adapter, and route persistence/audit + endpoint configuration. Extracted
// verbatim from index.js (monolith decomposition, Phase 1c). Route-status consts, sanitizers,
// CF payload/rule helpers and _ingestTokenB64Url are module-internal.
import { RUA_INBOUND_DOMAIN_DEFAULT, ingestDmarcReport, normalizeInboundRecipientDomain, sha256Hex } from "../lib/dmarc-ingest.js";
import { createAuditEvent } from "../lib/events.js";

// ── DMARC Aggregate Report Ingestion & Sender Intelligence v1 ────────────────
//
// Backend foundation for Managed DMARC. Parses manually imported DMARC RUA
// aggregate XML, rolls up sending sources, guesses providers from real sender
// signals, and computes cautious enforcement readiness. Manual import only —
// no inbound mail receiving, no managed mailbox, no dynamic DNS. All additive.






export function dmarcSenderRiskLevel(sender) {
  const c = sender.effective_classification || sender.classification || sender.auto_classification || "unknown";
  if (c === "threat" || c === "unauthorised") return "critical";
  if (c === "suspicious" || c === "misconfigured") return "high";
  if (c === "trusted" || c === "ignored") return "low";
  if (c === "authorised" || c === "likely_authorised" || c === "forwarder" || c === "mailing_list") return "low";
  const pr = typeof sender.pass_rate === "number" ? sender.pass_rate : 100;
  if (pr < 90 && (sender.total_messages || 0) >= 50) return "medium";
  return "low";
}
function dmarcSenderRecommendedAction(sender) {
  switch (sender.effective_classification || sender.classification) {
    case "trusted":    return "No action required. This sender is confirmed legitimate.";
    case "suspicious": return "Investigate this sender and confirm whether it is legitimate before enforcement.";
    case "threat":     return "Treat as impersonation. Confirm it is unauthorised and ensure DMARC enforcement blocks it.";
    case "ignored":    return "No action — this sender has been intentionally ignored.";
    case "authorised": return "This sender appears authorised from DMARC evidence. Keep the manual decision if your team has already reviewed it.";
    case "likely_authorised": return "This sender likely belongs to your business. Confirm it before tightening DMARC policy.";
    case "forwarder": return "This looks like forwarded mail. Confirm whether the forwarding path is expected before enforcement.";
    case "mailing_list": return "This looks like a mailing-list or campaign sender. Confirm ownership and alignment before enforcement.";
    case "misconfigured": return "This looks like a recognised sender with weak alignment. Fix SPF or DKIM alignment before enforcement.";
    case "unauthorised": return "Treat as likely unauthorised until confirmed. Review before moving to stricter DMARC enforcement.";
    default:           return "Classify this sender if it is a legitimate business email source.";
  }
}

// Enforcement-readiness v2 — the single structured model both the customer
// summary and the hosted autopilot speak. One evidence-based check set →
// numeric score → tri-state status, so "are we ready to tighten DMARC?" has a
// consistent, explainable answer instead of two engines disagreeing.
//
// A check is { id, label, status: 'pass'|'warn'|'fail', detail, weight }. Score
// is the weighted fraction of satisfied checks (warn = half credit), 0–100.
// Status: 'ready' (no fail + score ≥ 85), 'approaching' (score ≥ 55), else
// 'not_ready'. Hard blockers (alignment failures, active threats) can never sit
// in a 'ready' verdict because a single fail caps the status below ready.
export const ENFORCEMENT_CHECK_WEIGHTS = {
  dmarc_pass_rate: 25, sender_alignment: 20, no_active_threats: 15,
  reporting_window: 15, sender_classification: 10, message_volume: 10, soak_time: 5,
};

export function buildEnforcementReadinessChecks(summary = {}) {
  const days    = summary.days_with_data || 0;
  const total   = summary.total_messages || 0;
  const pass    = typeof summary.pass_rate === "number" ? summary.pass_rate : 0;
  const unknown = summary.unknown_senders || 0;
  const highVolFailed = summary.high_volume_failed_senders || 0;
  const threat  = summary.threat_senders || 0;
  const suspicious = summary.suspicious_senders || 0;
  const daysSinceChange = summary.days_since_change; // null/undefined = no change yet (n/a)

  const mk = (id, label, status, detail) => ({ id, label, status, detail, weight: ENFORCEMENT_CHECK_WEIGHTS[id] });
  const checks = [
    mk("dmarc_pass_rate", "DMARC pass rate",
       pass >= 98 ? "pass" : pass >= 95 ? "warn" : "fail",
       total > 0 ? `${pass}% of observed mail passes DMARC (98% recommended before reject).` : "No compliance measurement yet."),
    mk("sender_alignment", "Sender alignment",
       highVolFailed > 0 ? "fail" : "pass",
       highVolFailed > 0 ? `${highVolFailed} high-volume sender(s) fail SPF/DKIM alignment.` : "No high-volume sender is failing alignment."),
    mk("no_active_threats", "No active impersonation",
       threat > 0 ? "fail" : suspicious > 0 ? "warn" : "pass",
       threat > 0 ? `${threat} sender(s) are classified as impersonation threats.`
         : suspicious > 0 ? `${suspicious} sender(s) are still suspicious.` : "No confirmed or suspicious impersonation senders."),
    mk("reporting_window", "Reporting window",
       days >= 14 ? "pass" : days >= 7 ? "warn" : "fail",
       `${days} day(s) of DMARC reports imported (14+ recommended before reject).`),
    mk("sender_classification", "Sender classification",
       unknown === 0 ? "pass" : unknown <= 2 ? "warn" : "fail",
       unknown === 0 ? "Every observed sender is classified." : `${unknown} sender(s) remain unclassified.`),
    mk("message_volume", "Reporting volume",
       total >= 50 ? "pass" : total > 0 ? "warn" : "fail",
       total > 0 ? `${total} message(s) observed in the window.` : "No message volume observed yet."),
    mk("soak_time", "Soak time since last change",
       daysSinceChange == null ? "pass" : daysSinceChange >= 3 ? "pass" : daysSinceChange >= 1 ? "warn" : "fail",
       daysSinceChange == null ? "No recent policy change to soak." : `Last policy change was ${daysSinceChange} day(s) ago (allow 3).`),
  ];

  const maxScore = checks.reduce((a, c) => a + c.weight, 0);
  const earned = checks.reduce((a, c) => a + c.weight * (c.status === "pass" ? 1 : c.status === "warn" ? 0.5 : 0), 0);
  const score = maxScore > 0 ? Math.round((earned / maxScore) * 100) : 0;
  const anyFail = checks.some((c) => c.status === "fail");
  const status = (!anyFail && score >= 85) ? "ready" : score >= 55 ? "approaching" : "not_ready";
  return { status, score, checks };
}

/**
 * buildDmarcEnforcementReadiness(summary) — cautious enforcement guidance.
 * Never tells the user it is safe to reject all failing mail.
 *
 * Returns the legacy milestone keys (ready_for_quarantine / ready_for_reject /
 * confidence / blockers / next_step / explanation) unchanged for backward
 * compatibility, plus the unified v2 model (status / score / checks) from
 * buildEnforcementReadinessChecks so every surface shares one vocabulary.
 */
export function buildDmarcEnforcementReadiness(summary = {}) {
  const days    = summary.days_with_data || 0;
  const total   = summary.total_messages || 0;
  const pass    = typeof summary.pass_rate === "number" ? summary.pass_rate : 0;
  const unknown = summary.unknown_senders || 0;
  const highVolFailed = summary.high_volume_failed_senders || 0;

  const qBlockers = [];
  if (days < 7) qBlockers.push("Fewer than 7 days of DMARC reports have been imported.");
  if (total <= 0) qBlockers.push("No message volume has been observed yet.");
  if (pass < 95) qBlockers.push(`DMARC pass rate is ${pass}% (95% recommended before quarantine).`);
  if (unknown > 0) qBlockers.push(`${unknown} unknown sender${unknown === 1 ? "" : "s"} remain unclassified.`);
  if (highVolFailed > 0) qBlockers.push(`${highVolFailed} high-volume sender(s) are failing alignment.`);

  const rBlockers = [];
  if (days < 14) rBlockers.push("Fewer than 14 days of DMARC reports have been imported.");
  if (pass < 98) rBlockers.push(`DMARC pass rate is ${pass}% (98% recommended before reject).`);
  if (unknown > 0) rBlockers.push(`${unknown} unknown sender(s) must be classified first.`);
  if (highVolFailed > 0) rBlockers.push(`${highVolFailed} high-volume sender(s) are failing alignment.`);

  const readyQuarantine = qBlockers.length === 0;
  const readyReject     = rBlockers.length === 0;
  const blockers = readyQuarantine ? rBlockers : qBlockers; // surface the nearer milestone's blockers

  let confidence = "low";
  if (days >= 14 && total > 0) confidence = "high";
  else if (days >= 7 && total > 0) confidence = "medium";

  let next_step, explanation;
  if (readyReject) {
    next_step = "Your domain appears close to reject readiness, but confirm all legitimate senders before changing policy.";
    explanation = "Observed traffic is well aligned across an extended window. Validate every sender, then move towards p=reject with full coverage.";
  } else if (readyQuarantine) {
    next_step = "Your domain appears close to quarantine readiness, but confirm all legitimate senders before changing policy.";
    explanation = "Observed traffic is mostly aligned. Confirm legitimate senders, then move from p=none to p=quarantine.";
  } else {
    next_step = "Classify legitimate senders and improve alignment before moving to enforcement.";
    explanation = "The domain is not ready for enforcement yet. Resolve the blockers below, then re-evaluate.";
  }
  const v2 = buildEnforcementReadinessChecks(summary);
  return { ready_for_quarantine: readyQuarantine, ready_for_reject: readyReject, confidence, blockers, next_step, explanation,
           status: v2.status, score: v2.score, checks: v2.checks };
}


// Validate that a domain (hostname) belongs to a workspace; returns domain_id or null.
export async function resolveWorkspaceDomain(env, workspaceId, domain) {
  if (!workspaceId || !domain) return null;
  try {
    const row = await env.cybermeters_db
      .prepare(`SELECT d.id FROM domains d
                JOIN workspace_domains wd ON wd.domain_id = d.id
                WHERE wd.workspace_id = ? AND d.domain = ? LIMIT 1`)
      .bind(workspaceId, domain).first();
    return row?.id || null;
  } catch { return null; }
}

export async function loadEmailSenderSources(env, workspaceId, domain) {
  const rows = await env.cybermeters_db
    .prepare(`SELECT * FROM email_sender_sources
              WHERE workspace_id = ? AND domain = ? ORDER BY total_messages DESC`)
    .bind(workspaceId, domain).all();
  return rows.results || [];
}
export function summarizeEmailSenders(senders) {
  const s = { total_senders: senders.length, unknown_senders: 0, trusted_senders: 0,
    suspicious_senders: 0, threat_senders: 0, ignored_senders: 0,
    total_messages: 0, aligned_messages: 0, failed_messages: 0 };
  for (const x of senders) {
    s.total_messages   += x.total_messages || 0;
    s.aligned_messages += x.aligned_messages || 0;
    s.failed_messages  += x.failed_messages || 0;
    const c = x.classification || "unknown";
    if (c === "trusted") s.trusted_senders++;
    else if (c === "suspicious") s.suspicious_senders++;
    else if (c === "threat") s.threat_senders++;
    else if (c === "ignored") s.ignored_senders++;
    else s.unknown_senders++;
  }
  s.overall_pass_rate = s.total_messages > 0 ? Math.round((s.aligned_messages / s.total_messages) * 1000) / 10 : 0;
  return s;
}
export function emailSenderToApi(x) {
  let autoReasons = [];
  try {
    const parsed = typeof x.auto_reasons === "string" ? JSON.parse(x.auto_reasons) : x.auto_reasons;
    autoReasons = Array.isArray(parsed) ? parsed.map((r) => String(r).slice(0, 500)).slice(0, 8) : [];
  } catch { autoReasons = []; }
  const total = x.total_messages || 0;
  const spfAligned = x.spf_aligned_messages || 0;
  const dkimAligned = x.dkim_aligned_messages || 0;
  const spfRate = total > 0 ? Math.round((spfAligned / total) * 1000) / 10 : 0;
  const dkimRate = total > 0 ? Math.round((dkimAligned / total) * 1000) / 10 : 0;
  const manual = Boolean(x.classified_at);
  const effective = manual ? (x.classification || "unknown") : (x.auto_classification || x.classification || "unknown");
  const enriched = { ...x, effective_classification: effective };
  return {
    id: x.id, source_ip: x.source_ip,
    provider_guess: x.provider_guess, provider_confidence: x.provider_confidence, provider_reason: x.provider_reason,
    first_seen: x.first_seen, last_seen: x.last_seen,
    total_messages: x.total_messages || 0, aligned_messages: x.aligned_messages || 0, failed_messages: x.failed_messages || 0,
    spf_aligned_messages: spfAligned, dkim_aligned_messages: dkimAligned,
    spf_aligned_rate: spfRate, dkim_aligned_rate: dkimRate,
    quarantined_messages: x.quarantined_messages || 0, rejected_messages: x.rejected_messages || 0,
    pass_rate: typeof x.pass_rate === "number" ? x.pass_rate : 0,
    classification: x.classification || "unknown",
    effective_classification: effective,
    classification_source: manual ? "manual" : "auto",
    classified_at: x.classified_at || null,
    auto_classification: x.auto_classification || null,
    auto_confidence: typeof x.auto_confidence === "number" ? x.auto_confidence : null,
    auto_reasons: autoReasons,
    provider_map_version: x.provider_map_version || null,
    notes: x.notes || null,
    risk_level: dmarcSenderRiskLevel(enriched),
    recommended_action: dmarcSenderRecommendedAction(enriched),
  };
}

// ── Assisted DMARC Upload v1 — shared ingestion + signed-upload token model ───
//
// These helpers back the shared ingestion pipeline used by manual paste and the
// token-authenticated signed upload endpoint (and, in Phase 2, inbound RUA
// email). They never store or return raw XML, and the upload token is only ever
// persisted as a SHA-256 hash.



// High-entropy (256-bit) opaque upload token. Prefixed for identifiability in
// logs/UI; the prefix is not secret. The raw value is returned to the user once
// and never stored — only its SHA-256 hash is persisted.
function _ingestTokenB64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function generateIngestToken() {
  const bytes = new Uint8Array(32); // 256-bit
  crypto.getRandomValues(bytes);
  return `cmdi_${_ingestTokenB64Url(bytes)}`;
}
export async function hashIngestToken(raw) {
  return sha256Hex(String(raw || ""));
}
export function extractIngestToken(request) {
  const auth = request.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (m) return m[1].trim();
  const x = request.headers.get("X-CM-Ingest-Token");
  return x ? x.trim() : null;
}

const DMARC_ROUTE_STATUSES = new Set(["not_configured", "pending", "active", "failed", "revoked", "manual"]);
const DMARC_ROUTE_ERRORS = new Set([
  "missing_config", "api_rejected", "route_exists", "worker_not_found",
  "unsupported_api", "network_error", "unknown_error", "unsupported_domain",
  "unsupported_localpart", "auth_error", "rate_limited", "server_error",
]);

function sanitizeDmarcRouteStatus(status) {
  return DMARC_ROUTE_STATUSES.has(status) ? status : "failed";
}
function sanitizeDmarcRouteError(reason) {
  return reason && DMARC_ROUTE_ERRORS.has(reason) ? reason : (reason ? "unknown_error" : null);
}

// Customer-safe endpoint serialization. NEVER includes token_hash; only includes
// the raw token when explicitly passed (create/rotate response). When the
// endpoint has an inbound address_local, exposes the customer-facing RUA address
// and the exact rua=mailto: value to paste into DNS (display only — no auto-DNS).
export function ingestEndpointToApi(row, { rawToken = null, inboundDomain = null } = {}) {
  if (!row) return null;
  const host = inboundDomain || "reports.cybermeters.com";
  const inbound = row.address_local ? `${row.address_local}@${host}` : null;
  // Safe field allow-list only. Never serialize token_hash, the internal row id,
  // raw email, raw XML, or the MIME body. The raw token appears once, on
  // create/rotate, when explicitly passed in.
  const out = {
    domain: row.domain,
    address_local: row.address_local || null,
    inbound_address: inbound,
    rua_mailto: inbound ? `rua=mailto:${inbound}` : null,
    status: row.status,
    created_at: row.created_at,
    last_used_at: row.last_used_at || null,
    last_inbound_at: row.last_inbound_at || null,
    last_signed_upload_at: row.last_signed_upload_at || null,
    rotated_at: row.rotated_at || null,
    revoked_at: row.revoked_at || null,
    route_status: sanitizeDmarcRouteStatus(row.cloudflare_route_status || "not_configured"),
    route_error: sanitizeDmarcRouteError(row.cloudflare_route_error),
    route_updated_at: row.cloudflare_route_updated_at || null,
  };
  if (rawToken) out.token = rawToken;
  return out;
}

// ── Cloudflare Email Routing exact-address adapter ──────────────────────────
// Exact per-address routing is the safe public-beta strategy. Do not enable the
// zone-level catch-all: the UI catch-all appears zone-scoped, not subdomain-
// scoped. Each cmrua_...@reports.cybermeters.com address must use a literal
// `to` matcher and a worker action targeting cybermeters-platform.
const CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4";

export function _cloudflareRouteFailure(response, body) {
  const messages = Array.isArray(body?.errors)
    ? body.errors.map((error) => String(error?.message || "").toLowerCase()).join(" ") : "";
  if (response?.status === 404 || response?.status === 405) return "unsupported_api";
  // Distinguish permanent config faults from transient ones so callers can
  // stop hammering on a bad token yet keep retrying rate-limits/outages.
  if (response?.status === 401 || response?.status === 403) return "auth_error";
  if (response?.status === 429) return "rate_limited";
  if (response && response.status >= 500) return "server_error";
  if (/worker/.test(messages) && /(not found|does not exist|unknown)/.test(messages)) return "worker_not_found";
  if (/(already exists|duplicate)/.test(messages)) return "route_exists";
  if (response && !response.ok) return "api_rejected";
  return "unknown_error";
}

// Maps a Cloudflare failure reason to a customer-safe issue class for hosted
// records: config_error is on us (bad/insufficient token) and must surface;
// temporary_issue is transient (rate-limit, outage, network) and self-heals on
// the next hourly sweep.
export function classifyHostedCfError(reason) {
  if (reason === "auth_error" || reason === "missing_config") return "config_error";
  return "temporary_issue";
}

export async function _cloudflareEmailRoutingRequest(env, path, init = {}, fetchImpl = fetch) {
  // Transient CF throttling (429) / unavailability (503) gets a short, bounded
  // in-request backoff (honour Retry-After, capped) with jitter. Persistent
  // failures fall through to the caller — the Hosted Records write-ahead intent
  // survives and the sweep reconciler retries later — so we never wait long here.
  const MAX_ATTEMPTS = 3;
  let response;
  for (let attempt = 1; ; attempt++) {
    try {
      response = await fetchImpl(`${CLOUDFLARE_API_BASE}${path}`, {
        ...init,
        headers: {
          Authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
          "Content-Type": "application/json",
          ...(init.headers || {}),
        },
      });
    } catch {
      return { ok: false, reason: "network_error" };
    }
    if ((response.status === 429 || response.status === 503) && attempt < MAX_ATTEMPTS) {
      const retryAfter = Number(response.headers.get("Retry-After"));
      const waitMs = Number.isFinite(retryAfter) && retryAfter > 0
        ? Math.min(retryAfter * 1000, 2000)
        : Math.min(400 * 2 ** (attempt - 1), 1500) + Math.floor(Math.random() * 250);
      await new Promise((r) => setTimeout(r, waitMs));
      continue;
    }
    break;
  }
  let body;
  try { body = await response.json(); }
  catch { return { ok: false, reason: response.status === 404 || response.status === 405 ? "unsupported_api" : "api_rejected" }; }
  if (!response.ok || body?.success !== true) return { ok: false, reason: _cloudflareRouteFailure(response, body) };
  return { ok: true, body };
}

function _cloudflareExactRoutePayload(addressLocal, domain, workerName) {
  const address = `${addressLocal}@${domain}`;
  return {
    actions: [{ type: "worker", value: [workerName] }],
    matchers: [{ type: "literal", field: "to", value: address }],
    enabled: true,
    name: `CyberMeters RUA ${address}`,
  };
}

function _cloudflareRuleMatchesExactWorker(rule, address, workerName) {
  const literal = Array.isArray(rule?.matchers) && rule.matchers.some((matcher) =>
    matcher?.type === "literal" && matcher?.field === "to" && matcher?.value?.toLowerCase() === address);
  const worker = Array.isArray(rule?.actions) && rule.actions.some((action) =>
    action?.type === "worker" && Array.isArray(action.value) && action.value.includes(workerName));
  return literal && worker && rule.enabled === true;
}

export async function ensureCloudflareEmailRoute(env, addressLocal, domain, { fetchImpl = fetch } = {}) {
  const inboundDomain = normalizeInboundRecipientDomain(env?.RUA_INBOUND_DOMAIN || RUA_INBOUND_DOMAIN_DEFAULT);
  const requestedDomain = normalizeInboundRecipientDomain(domain);
  if (!requestedDomain || requestedDomain !== inboundDomain || requestedDomain === "cybermeters.com") {
    return { ok: false, status: "failed", reason: "unsupported_domain" };
  }
  if (typeof addressLocal !== "string" || !/^cmrua_[a-z0-9]{8,}$/.test(addressLocal) ||
      addressLocal.includes("*") || addressLocal.includes("@")) {
    return { ok: false, status: "failed", reason: "unsupported_localpart" };
  }
  const token = String(env?.CLOUDFLARE_API_TOKEN || "").trim();
  const zoneId = String(env?.CLOUDFLARE_ZONE_ID || "").trim();
  const workerName = String(env?.CLOUDFLARE_EMAIL_ROUTING_WORKER_NAME || "cybermeters-platform").trim();
  if (!token || !/^[a-f0-9]{32}$/i.test(zoneId) || !/^[a-z0-9][a-z0-9_-]{0,62}$/i.test(workerName)) {
    return { ok: false, status: "not_configured", reason: "missing_config" };
  }

  const address = `${addressLocal}@${requestedDomain}`;
  const basePath = `/zones/${zoneId}/email/routing/rules`;
  let existing = null;
  let page = 1;
  let totalPages = 1;
  do {
    const listed = await _cloudflareEmailRoutingRequest(env, `${basePath}?page=${page}&per_page=50`, {}, fetchImpl);
    if (!listed.ok) return { ok: false, status: "failed", reason: listed.reason };
    const rules = Array.isArray(listed.body?.result) ? listed.body.result : [];
    existing = rules.find((rule) => Array.isArray(rule?.matchers) && rule.matchers.some((matcher) =>
      matcher?.type === "literal" && matcher?.field === "to" && matcher?.value?.toLowerCase() === address));
    totalPages = Math.min(Math.max(Number(listed.body?.result_info?.total_pages) || 1, 1), 100);
    page++;
  } while (!existing && page <= totalPages);

  const payload = _cloudflareExactRoutePayload(addressLocal, requestedDomain, workerName);
  if (existing && _cloudflareRuleMatchesExactWorker(existing, address, workerName)) {
    return { ok: true, status: "active", route_id: existing.id || null, message: "route_exists" };
  }
  if (existing && (typeof existing.id !== "string" || !/^[a-z0-9]{1,32}$/i.test(existing.id))) {
    return { ok: false, status: "failed", reason: "unknown_error" };
  }
  const method = existing ? "PUT" : "POST";
  const path = existing ? `${basePath}/${encodeURIComponent(existing.id)}` : basePath;
  const saved = await _cloudflareEmailRoutingRequest(env, path, {
    method, body: JSON.stringify(payload),
  }, fetchImpl);
  if (!saved.ok) return { ok: false, status: "failed", reason: saved.reason };
  const routeId = saved.body?.result?.id;
  if (!routeId || typeof routeId !== "string") return { ok: false, status: "failed", reason: "unknown_error" };
  return { ok: true, status: "active", route_id: routeId,
    message: existing ? "route_updated" : "route_created" };
}

export async function safelyEnsureCloudflareEmailRoute(env, addressLocal, domain, options = {}) {
  try { return await ensureCloudflareEmailRoute(env, addressLocal, domain, options); }
  catch { return { ok: false, status: "failed", reason: "unknown_error" }; }
}

export async function revokeCloudflareEmailRoute(env, routeId, { fetchImpl = fetch } = {}) {
  if (!routeId) return { ok: true, status: "revoked", route_id: null, message: "no_managed_route" };
  if (typeof routeId !== "string" || !/^[a-z0-9]{1,32}$/i.test(routeId)) {
    return { ok: false, status: "failed", reason: "unknown_error", route_id: routeId || null };
  }
  const token = String(env?.CLOUDFLARE_API_TOKEN || "").trim();
  const zoneId = String(env?.CLOUDFLARE_ZONE_ID || "").trim();
  if (!token || !/^[a-f0-9]{32}$/i.test(zoneId)) {
    return { ok: false, status: "failed", reason: "missing_config", route_id: routeId };
  }
  const removed = await _cloudflareEmailRoutingRequest(
    env, `/zones/${zoneId}/email/routing/rules/${encodeURIComponent(routeId)}`,
    { method: "DELETE" }, fetchImpl
  );
  if (!removed.ok) return { ok: false, status: "failed", reason: removed.reason, route_id: routeId };
  return { ok: true, status: "revoked", route_id: routeId, message: "route_revoked" };
}

export async function safelyRevokeCloudflareEmailRoute(env, routeId, options = {}) {
  try { return await revokeCloudflareEmailRoute(env, routeId, options); }
  catch { return { ok: false, status: "failed", reason: "unknown_error", route_id: routeId || null }; }
}

export async function persistDmarcRouteResult(env, endpointId, result) {
  const status = sanitizeDmarcRouteStatus(result?.status);
  const error = result?.ok ? null : sanitizeDmarcRouteError(result?.reason);
  const routeId = typeof result?.route_id === "string" ? result.route_id : null;
  await env.cybermeters_db
    .prepare(`UPDATE dmarc_ingest_endpoints
              SET cloudflare_route_id = COALESCE(?, cloudflare_route_id),
                  cloudflare_route_status = ?, cloudflare_route_error = ?,
                  cloudflare_route_created_at = CASE WHEN ? = 'active'
                    THEN COALESCE(cloudflare_route_created_at, datetime('now')) ELSE cloudflare_route_created_at END,
                  cloudflare_route_updated_at = datetime('now')
              WHERE id = ?`)
    .bind(routeId, status, error, status, endpointId).run();
  return { status, error, route_id: routeId };
}

export async function auditDmarcRouteResult(env, endpoint, actorUserId, result, operation = "ensure") {
  const status = sanitizeDmarcRouteStatus(result?.status);
  const reason = result?.ok ? null : sanitizeDmarcRouteError(result?.reason);
  let eventType = "dmarc_ingest_route_failed";
  if (operation === "revoke" && result?.ok) eventType = "dmarc_ingest_route_revoked";
  else if (result?.ok) eventType = "dmarc_ingest_route_created";
  else if (status === "not_configured") eventType = "dmarc_ingest_route_skipped";
  await createAuditEvent(env, {
    workspace_id: endpoint.workspace_id, user_id: actorUserId, event_type: eventType,
    entity_type: "domain", entity_id: endpoint.domain_id,
    description: `${operation === "revoke" ? "Cloudflare DMARC route revoke" : "Cloudflare DMARC route automation"} ${status}`,
    metadata: {
      domain: endpoint.domain,
      recipient_localpart: endpoint.address_local || null,
      route_status: status,
      reason,
      operation,
      source: "cloudflare_email_routing",
    },
  });
}

// RFC 7489 §7.1 — external destination verification. A receiver only sends
// aggregate reports for <domain> to a cross-org rua address if
// <domain>._report._dmarc.<rua-domain> publishes a DMARC TXT record. Without
// it, external reporters (Google, Microsoft, …) silently send nothing — the
// exact failure mode that stalled the first external pilot. Same-org
// destinations (rua domain equal to or under the report domain, e.g.
// reports.cybermeters.com for cybermeters.com) are exempt per the RFC, so
// nothing is provisioned for them. Idempotent: adopts an existing record at
// the name instead of creating duplicates. Never throws.
export async function ensureExternalReportAuthorization(env, domain, { fetchImpl = fetch } = {}) {
  const inboundDomain = normalizeInboundRecipientDomain(env?.RUA_INBOUND_DOMAIN || RUA_INBOUND_DOMAIN_DEFAULT);
  const reportDomain = normalizeInboundRecipientDomain(domain);
  if (!inboundDomain || !reportDomain) return { ok: false, reason: "invalid_domain" };
  // Same-org test without a PSL: our inbound domain is always one label under
  // our organizational domain (reports.<org>), so dropping that label yields
  // the org domain. Exempts the org apex AND sibling subdomains
  // (app.cybermeters.com), not just ancestors of the inbound domain.
  const inboundOrg = inboundDomain.split(".").slice(1).join(".");
  if (
    inboundDomain === reportDomain ||
    inboundDomain.endsWith(`.${reportDomain}`) ||
    (inboundOrg && (reportDomain === inboundOrg || reportDomain.endsWith(`.${inboundOrg}`)))
  ) {
    return { ok: true, skipped: "same_org" };
  }
  const zoneId = String(env?.CLOUDFLARE_ZONE_ID || "").trim();
  if (!String(env?.CLOUDFLARE_API_TOKEN || "").trim() || !/^[a-f0-9]{32}$/i.test(zoneId)) {
    return { ok: false, reason: "missing_config" };
  }
  const name = `${reportDomain}._report._dmarc.${inboundDomain}`;
  const base = `/zones/${zoneId}/dns_records`;
  const listed = await _cloudflareEmailRoutingRequest(
    env, `${base}?type=TXT&name=${encodeURIComponent(name)}&per_page=5`, {}, fetchImpl);
  if (listed.ok) {
    const matches = Array.isArray(listed.body?.result) ? listed.body.result : [];
    const existing = matches.find((r) => /v\s*=\s*DMARC1/i.test(String(r?.content || "")));
    if (existing) return { ok: true, cf_record_id: existing.id || null, adopted: true };
  } else if (listed.reason && listed.reason !== "unsupported_api") {
    return { ok: false, reason: listed.reason };
  }
  const res = await _cloudflareEmailRoutingRequest(env, base, {
    method: "POST",
    body: JSON.stringify({
      type: "TXT",
      name,
      content: "v=DMARC1;",
      ttl: 3600,
      comment: "CyberMeters RUA external report authorization (RFC 7489 7.1)",
    }),
  }, fetchImpl);
  if (!res.ok) return { ok: false, reason: res.reason || "api_rejected" };
  return { ok: true, cf_record_id: res.body?.result?.id || null, created: true };
}

export async function configureDmarcEndpointRoute(env, endpoint, actorUserId, options = {}) {
  const inboundDomain = env.RUA_INBOUND_DOMAIN || RUA_INBOUND_DOMAIN_DEFAULT;
  const result = await safelyEnsureCloudflareEmailRoute(env, endpoint.address_local, inboundDomain, options);
  await persistDmarcRouteResult(env, endpoint.id, result);
  await auditDmarcRouteResult(env, endpoint, actorUserId, result, "ensure");
  // The RFC 7489 §7.1 authorization record rides along with every route
  // provisioning pass, so re-configuring an endpoint self-heals a missing
  // record. A failure never blocks route setup — the ops runbook still covers
  // manual creation and the next configure call retries.
  try {
    const auth = await ensureExternalReportAuthorization(env, endpoint.domain, options);
    if (!auth.ok) {
      console.error("[rua] report-authorization not ensured", JSON.stringify({
        endpoint_id: endpoint.id, domain: endpoint.domain, reason: auth.reason,
      }));
    } else if (!auth.skipped) {
      console.log("[rua] report-authorization ensured", JSON.stringify({
        endpoint_id: endpoint.id, domain: endpoint.domain,
        created: !!auth.created, cf_record_id: auth.cf_record_id || null,
      }));
    }
  } catch (e) {
    console.error("[rua] report-authorization error", e?.message);
  }
  return result;
}


// ── Assisted RUA Ingestion v1 (Phase 2) — inbound email helpers ───────────────
//
// Pure, testable helpers that turn a raw inbound DMARC report email into an XML
// string for ingestDmarcReport(). They never fetch, never expand entities, never
// store raw payloads, and enforce hard size/ratio caps to defeat decompression
// bombs. The Worker email() handler wires these together (see the email entry).

export function generateInboundLocalpart() {
  const bytes = new Uint8Array(16); // 128-bit
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  return `cmrua_${hex}`;
}
