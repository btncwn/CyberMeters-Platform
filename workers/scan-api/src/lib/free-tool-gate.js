// ── Shared gate for the public free tools (/api/tools/*) ─────────────────────
//
// Every free tool endpoint goes through these checks, in this order, so a
// refused request costs no D1 write and no outbound lookup:
//
//   1. input: a public domain name only (no IP, port, path, internal name)
//   2. Turnstile, verified server-side (signed-in workspace users skip it)
//   3. limiter, read-only: refuse now if a limit is already full
//   4. per-domain result cache (a hit returns here and counts against nothing)
//   5. limiter, atomic claim (per IP or per user, per domain, global budget)
//   6. the lookup itself, bounded by a subrequest counter and a deadline
//
// Limits use the canonical D1 limiter (lib/rate-limit.js), atomic and fail
// closed: if the limiter cannot answer, the tool refuses. Only hashed rate-limit
// keys are stored; the queried domain and the visitor's IP are not.
import { hostIsPrivateOrReserved } from "./ssrf.js";
import { canonicalDomainInput, isValidDomain } from "./util.js";

export const FREE_TOOL_IDS = Object.freeze(["dmarc", "spf", "headers", "lookalike"]);

export const FREE_TOOL_POLICY = Object.freeze({
  // Anonymous visitors: each tool at most twice per IP per rolling 24 hours.
  ipRuns: 2,
  ipWindowSeconds: 24 * 3600,
  // Per target domain, whoever asks (a botnet can rotate IPs, not targets).
  domainRuns: 10,
  domainWindowSeconds: 3600,
  // Signed-in workspace users skip Turnstile and the IP limit; this per-user
  // ceiling only stops a runaway script.
  userRuns: 50,
  userWindowSeconds: 24 * 3600,
  // Emergency breaker for all tools together, far above real demand. When it
  // trips nobody is turned away: they can leave an email for the result.
  dailyBudget: 20000,
  budgetWindowSeconds: 24 * 3600,
  alertFractions: Object.freeze([0.5, 0.8]),
  cacheSeconds: 600,
  // Deferred results while the breaker is tripped.
  deferIpRuns: 2,
  deferPendingMax: 2000,
  deferMaxAgeHours: 72,
  deferBatch: 10,
  deferMaxAttempts: 3,
  // Per lookup.
  subrequestLimit: 120,
  deadlineMs: 10_000,
  maxBodyBytes: 4096,
});

// Names that are never public DNS even though they look like domains.
const NON_PUBLIC_TLDS = new Set(["arpa", "alt"]);

/**
 * The domain a visitor typed → a bare public hostname, or a refusal.
 * A scheme and a trailing slash are tolerated (people paste URLs); a path,
 * query, port or credentials are refused rather than silently dropped, so the
 * result is never about something other than what was typed.
 */
export function normaliseToolDomain(raw) {
  const refuse = { ok: false, code: "invalid_domain", message: "Enter a domain name such as example.com, without a path or port." };
  if (typeof raw !== "string") return refuse;
  let value = raw.trim().toLowerCase();
  if (!value || value.length > 300) return refuse;
  value = value.replace(/^https?:\/\//, "").replace(/\/$/, "").replace(/\.+$/, "");
  if (/[/?#@:\s\\[\]]/.test(value)) return refuse;
  const domain = canonicalDomainInput(value, { stripWww: true });
  if (!domain || !isValidDomain(domain)) return refuse;
  const tld = domain.split(".").at(-1);
  if (NON_PUBLIC_TLDS.has(tld) || hostIsPrivateOrReserved(domain)) {
    return { ok: false, code: "non_public_domain", message: "That name is not a public domain, so there is nothing to check from the internet." };
  }
  return { ok: true, domain };
}

// Second-level labels under a two-letter ccTLD that are public suffixes, so the
// per-domain cap counts example.co.uk, not co.uk. Mirrors lib/util.js.
const CC_SECOND_LEVEL = new Set(["co", "com", "org", "net", "ac", "gov", "edu", "ltd", "plc", "me", "sch", "nhs", "police", "mod", "nic"]);

/** The key the per-domain cap counts: the registrable part of the hostname. */
export function domainCapKey(domain) {
  const labels = String(domain).split(".");
  const tld = labels.at(-1);
  const second = labels.at(-2);
  const take = labels.length >= 3 && tld.length === 2 && CC_SECOND_LEVEL.has(second) ? 3 : 2;
  return labels.slice(-take).join(".");
}

// ── Turnstile ───────────────────────────────────────────────────────────────

const TURNSTILE_SITEVERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/**
 * Verify a Turnstile token server-side before any lookup. Fails closed: a
 * missing secret, a timeout or an unreadable answer all refuse.
 */
export async function verifyTurnstile(env, token, { remoteIp = null, action = null, fetchImpl = fetch, timeoutMs = 4000 } = {}) {
  const secret = typeof env?.TURNSTILE_SECRET_KEY === "string" ? env.TURNSTILE_SECRET_KEY.trim() : "";
  if (!secret) return { ok: false, status: 503, code: "verification_unavailable" };
  if (typeof token !== "string" || !token.trim() || token.length > 2048) {
    return { ok: false, status: 400, code: "verification_required" };
  }
  const body = new URLSearchParams({ secret, response: token.trim() });
  if (remoteIp) body.set("remoteip", remoteIp);
  let outcome;
  try {
    const response = await fetchImpl(TURNSTILE_SITEVERIFY, {
      method: "POST",
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) return { ok: false, status: 503, code: "verification_unavailable" };
    outcome = await response.json();
  } catch {
    return { ok: false, status: 503, code: "verification_unavailable" };
  }
  if (outcome?.success !== true) return { ok: false, status: 403, code: "verification_failed" };
  // A token made for one tool cannot be spent on another.
  if (action && outcome.action !== action) return { ok: false, status: 403, code: "verification_failed" };
  return { ok: true };
}

// ── Result cache (Cloudflare Cache API, per data centre, 10 minutes) ─────────

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

// The key carries a hash, never the domain itself.
async function cacheRequest(tool, domain) {
  return new Request(`https://api.cybermeters.com/__free-tools-cache/v1/${tool}/${await sha256Hex(`${tool}:${domain}`)}`);
}

export function defaultToolCache() {
  try {
    return globalThis.caches?.default ?? null;
  } catch {
    return null;
  }
}

/** Cached result for this tool and domain, or null. A cache error is a miss. */
export async function readToolCache(cache, tool, domain) {
  if (!cache) return null;
  try {
    const hit = await cache.match(await cacheRequest(tool, domain));
    if (!hit) return null;
    const result = await hit.json();
    return result?.tool === tool && result?.domain === domain ? result : null;
  } catch {
    return null;
  }
}

export async function writeToolCache(cache, tool, domain, result, seconds = FREE_TOOL_POLICY.cacheSeconds) {
  if (!cache) return;
  try {
    await cache.put(await cacheRequest(tool, domain), new Response(JSON.stringify(result), {
      headers: { "Content-Type": "application/json", "Cache-Control": `public, max-age=${seconds}` },
    }));
  } catch {
    // A cache that cannot be written only means the next request looks again.
  }
}
