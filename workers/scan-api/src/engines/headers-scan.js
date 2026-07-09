// ── HTTP headers / bot-protection scan module ──
// Security-headers analysis (HSTS/CSP/XFO/etc. strength classification) + bot/edge
// protection detection, plus the runHeadersModule scan phase. Extracted verbatim from
// index.js (monolith decomposition, Phase 1c). Internal: BOT_CHALLENGE_URL_PATTERNS,
// HEADER_PROBE_INIT, detectBotProtection. classifyHeaderStrength is also used elsewhere.
import { safeFetch } from "../lib/http.js";

// ── Bot Protection & Challenge Detection ─────────────────────────────────────
//
// Enterprise ASM scanners are regularly served challenge pages rather than the
// actual application.  Generating Missing-HSTS / Missing-CSP findings against a
// Cloudflare managed-challenge or a Google consent redirect produces embarrassing
// false positives.  detectBotProtection() identifies these responses so the
// scoring engine can emit informational observations instead of real findings.

const BOT_CHALLENGE_URL_PATTERNS = [
  "consent.google.com",
  "accounts.google.com/ServiceLogin",
  "accounts.google.com/o/oauth",
  "challenges.cloudflare.com",
  "/sorry/index",
  "/sorry/",
  "gateway.google.com",
  "/captcha",
  "bot-manager.",
  "perimeter81.",
];

// Scanner identification — honest UA, not impersonation
const HEADER_PROBE_INIT = {
  headers: {
    "User-Agent":      "Mozilla/5.0 (compatible; CyberMeters-Scanner/1.0; +https://cybermeters.com/scanner)",
    "Accept":          "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
  },
};

/**
 * Returns an array of signal strings describing detected bot/edge protection.
 * Empty array → no evidence of interception; non-empty → validation uncertain.
 *
 * @param {number}  statusCode   HTTP status of the response
 * @param {string}  responseUrl  Final URL after redirects (res.url)
 * @param {object}  headerMap    Lower-cased headers as { name: value } object
 */
function detectBotProtection(statusCode, responseUrl, headerMap) {
  const signals = [];

  // 1. Challenge / consent redirect — final URL ended up somewhere unexpected
  if (responseUrl) {
    for (const pat of BOT_CHALLENGE_URL_PATTERNS) {
      if (responseUrl.includes(pat)) {
        signals.push(`challenge_redirect:${pat}`);
        break;
      }
    }
  }

  // 2. Cloudflare managed challenge explicit header
  const cfMitigated = (headerMap["cf-mitigated"] || "").toLowerCase();
  if (cfMitigated === "challenge") signals.push("cf_managed_challenge");

  // 3. Imperva / Incapsula
  if (headerMap["x-iinfo"] || headerMap["x-cdn"] === "imperva") {
    signals.push("imperva_protection");
  }

  // 4. Hard rate-limit with Retry-After
  if ([429, 503].includes(statusCode) && headerMap["retry-after"]) {
    signals.push(`rate_limited_${statusCode}`);
  }

  // 5. 200 OK but no Content-Type AND no Server header → minimal/challenge response
  //    Real pages virtually always return Content-Type.
  if (statusCode === 200 && !headerMap["content-type"] && !headerMap["server"]) {
    signals.push("minimal_response_on_200");
  }

  return signals;
}

// ── Module 3: Security Headers Analysis ──────────────────────────────────────

/**
 * classifyHeaderStrength(name, value)
 *
 * Returns { status, details } for a security header value.
 * status: "valid" | "weak" | "malformed" | "unknown"
 *
 * Criteria (v4 — Sprint: Scanner Accuracy Validation v4):
 *   HSTS:                 valid if max-age >= 15,552,000 (180d); weak if 0 < max-age < 180d; malformed if unparsable
 *   CSP:                  valid if present and no obvious dangerous directives; weak if contains unsafe-inline / wildcard-only
 *   X-Frame-Options:      valid if DENY or SAMEORIGIN; malformed otherwise
 *   X-Content-Type-Options: valid if nosniff; malformed otherwise
 *   Referrer-Policy:      valid if strict value; weak if unsafe-url or no-referrer-when-downgrade
 *   Permissions-Policy:   valid if present (content-agnostic); unknown if cannot validate
 */
export function classifyHeaderStrength(name, value) {
  const n = (name || "").toLowerCase().trim();
  const v = (value || "").toLowerCase().trim();

  if (n === "strict-transport-security") {
    const m = v.match(/max-age\s*=\s*(\d+)/i);
    if (!m) return { status: "malformed", details: "HSTS header present but max-age is missing or unparsable" };
    const maxAge = parseInt(m[1], 10);
    if (maxAge >= 15_552_000) return { status: "valid",   details: `max-age=${maxAge} (≥180 days)` };
    if (maxAge > 0)           return { status: "weak",    details: `max-age=${maxAge} — below recommended minimum of 15,552,000 (180 days)` };
    return { status: "malformed", details: "max-age=0 disables HSTS protection" };
  }

  if (n === "content-security-policy") {
    if (!v) return { status: "unknown", details: "CSP present but value is empty" };
    const hasUnsafeInline  = /unsafe-inline/i.test(v);
    const hasUnsafeEval    = /unsafe-eval/i.test(v);
    const wildcardDefault  = /default-src\s+['"]?\*['"]?/.test(v);
    const wildcardScript   = /script-src\s+['"]?\*['"]?/.test(v);
    if (wildcardDefault || wildcardScript) return { status: "weak", details: "CSP contains wildcard default-src or script-src — effectively disabled" };
    if (hasUnsafeInline || hasUnsafeEval)  return { status: "weak", details: `CSP contains ${hasUnsafeInline ? "'unsafe-inline'" : ""}${hasUnsafeEval ? " 'unsafe-eval'" : ""} — reduces XSS protection` };
    return { status: "valid", details: "CSP present with no immediately dangerous directives detected" };
  }

  if (n === "x-frame-options") {
    if (v === "deny" || v === "sameorigin") return { status: "valid", details: `X-Frame-Options: ${value}` };
    if (v.startsWith("allow-from"))         return { status: "weak",  details: "ALLOW-FROM is deprecated and inconsistently supported; use CSP frame-ancestors instead" };
    return { status: "malformed", details: `Unrecognised X-Frame-Options value: "${value}"` };
  }

  if (n === "x-content-type-options") {
    if (v === "nosniff") return { status: "valid", details: "nosniff" };
    return { status: "malformed", details: `Expected "nosniff", got "${value}"` };
  }

  if (n === "referrer-policy") {
    const strict = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"];
    const weak   = ["unsafe-url", "no-referrer-when-downgrade"];
    if (strict.includes(v)) return { status: "valid", details: v };
    if (weak.includes(v))   return { status: "weak",  details: `${v} — sends referrer to cross-origin requests` };
    if (!v)                 return { status: "weak",  details: "Empty referrer-policy defaults to browser behaviour (usually unsafe-url)" };
    return { status: "valid", details: v };
  }

  if (n === "permissions-policy") {
    return { status: "valid", details: "Permissions-Policy present (content not validated)" };
  }

  return { status: "unknown", details: `Header "${name}" strength classification not implemented` };
}

export async function runHeadersModule(domain) {
  let headerValues         = {};
  let accessible           = false;
  let statusCode           = null;
  let originalUrl          = null;
  let responseUrl          = null;
  let redirectCount        = 0;
  let setCookieRaw         = [];
  let botProtectionSignals = [];
  let rawHeaderSnapshot    = {};   // all response headers for diagnostics / bot detection
  const checkedPaths       = [];

  const snapshotHeaders = (headers) => {
    const out = {};
    headers.forEach((v, k) => { out[k.toLowerCase()] = v; });
    return out;
  };

  const securityHeaderValues = (headers) => {
    const values = {};
    for (const h of SECURITY_HEADERS) values[h.name] = headers.get(h.name) || null;
    return values;
  };

  const recordHeaderCheck = (label, requestedUrl, res, method = "GET") => {
    if (!res) {
      checkedPaths.push({
        label,
        requested_url: requestedUrl,
        method,
        status: "unavailable",
        final_url: null,
        status_code: null,
        redirect_chain: [],
        headers_observed: {},
      });
      return {};
    }
    const observed = securityHeaderValues(res.headers);
    checkedPaths.push({
      label,
      requested_url: requestedUrl,
      method,
      status: "ok",
      final_url: res.url,
      status_code: res.status,
      redirect_chain: res.url && res.url !== requestedUrl ? [{ from: requestedUrl, to: res.url }] : [],
      headers_observed: observed,
    });
    return observed;
  };

  // Prefer HTTPS; fall back to HTTP.
  // redirect:"follow" → res.url is the final URL after all redirects (Fetch API spec).
  for (const proto of ["https", "http"]) {
    const probeUrl = `${proto}://${domain}`;

    // ── Step 1: GET (primary) ─────────────────────────────────────────────
    const getRes = await safeFetch(probeUrl, {
      method:   "GET",
      redirect: "follow",
      ...HEADER_PROBE_INIT,
    });
    if (!getRes) continue;

    accessible    = true;
    statusCode    = getRes.status;
    originalUrl   = probeUrl;
    responseUrl   = getRes.url;
    redirectCount = (getRes.url && getRes.url !== probeUrl) ? 1 : 0;

    // Snapshot every response header (lower-cased) for bot-protection detection
    rawHeaderSnapshot = snapshotHeaders(getRes.headers);

    // Read security headers from GET response
    headerValues = recordHeaderCheck("/", probeUrl, getRes, "GET");
    if (responseUrl && responseUrl !== probeUrl) {
      checkedPaths.push({
        label: "final_canonical_url",
        requested_url: responseUrl,
        method: "GET",
        status: "ok",
        final_url: responseUrl,
        status_code: getRes.status,
        redirect_chain: [],
        headers_observed: { ...headerValues },
      });
    }

    // Set-Cookie capture — Workers supports getAll() because multiple values
    // can't be safely comma-joined.
    try {
      setCookieRaw = typeof getRes.headers.getAll === "function"
        ? getRes.headers.getAll("set-cookie")
        : (getRes.headers.get("set-cookie") || "").split(/\r?\n/).filter(Boolean);
    } catch { setCookieRaw = []; }

    // ── Step 2: Bot protection detection ─────────────────────────────────
    botProtectionSignals = detectBotProtection(statusCode, responseUrl, rawHeaderSnapshot);

    if (botProtectionSignals.length > 0) {
      // GET was intercepted by an edge challenge.  Try HEAD — some WAFs skip
      // challenge injection on HEAD requests, potentially returning real headers.
      const headRes = await safeFetch(probeUrl, {
        method:   "HEAD",
        redirect: "follow",
        ...HEADER_PROBE_INIT,
      });
      if (headRes) {
        const headSnapshot = snapshotHeaders(headRes.headers);
        const headBotSignals = detectBotProtection(headRes.status, headRes.url, headSnapshot);

        // Count how many security headers each response provides
        const getSecCount  = SECURITY_HEADERS.filter(h => headerValues[h.name]).length;
        const headSecCount = SECURITY_HEADERS.filter(h => headRes.headers.get(h.name)).length;

        // Prefer the response with more security headers or fewer bot signals
        if (headSecCount > getSecCount || headBotSignals.length < botProtectionSignals.length) {
          for (const h of SECURITY_HEADERS) {
            headerValues[h.name] = headRes.headers.get(h.name) || null;
          }
          botProtectionSignals = headBotSignals;
          statusCode  = headRes.status;
          responseUrl = headRes.url;
          rawHeaderSnapshot = headSnapshot;
        }
      }
    }

    if (!domain.startsWith("www.")) {
      const wwwUrl = `${proto}://www.${domain}`;
      const wwwRes = await safeFetch(wwwUrl, {
        method:   "HEAD",
        redirect: "follow",
        ...HEADER_PROBE_INIT,
      });
      recordHeaderCheck("www_variant", wwwUrl, wwwRes, "HEAD");
    }

    break;
  }

  // Whether the final response came over HTTPS.
  // HSTS is only meaningful on HTTPS — used in computeScore to avoid false positives
  // when we had to fall back to plain HTTP.
  const finalHttps = responseUrl ? responseUrl.startsWith("https://") : false;

  const present = SECURITY_HEADERS.filter((h) => !!headerValues[h.name]).map((h) => h.name);
  const missing = SECURITY_HEADERS.filter((h) => !headerValues[h.name]).map((h) => h.name);

  return {
    accessible,
    status_code:            statusCode,
    original_url:           originalUrl,
    response_url:           responseUrl,
    redirect_count:         redirectCount,
    final_https:            finalHttps,
    validation_uncertain:   botProtectionSignals.length > 0,
    bot_protection_signals: botProtectionSignals,
    raw_capture: {
      status:         statusCode,
      final_url:      responseUrl,
      redirect_chain: redirectCount > 0 ? [{ from: originalUrl, to: responseUrl }] : [],
      headers_snapshot: rawHeaderSnapshot,
    },
    checked_paths: checkedPaths,
    present,
    missing,
    values:         headerValues,
    set_cookie_raw: setCookieRaw,
    // v4: Header strength classification per security header
    header_strength: Object.fromEntries(
      SECURITY_HEADERS
        .filter((h) => headerValues[h.name])
        .map((h) => [h.name, classifyHeaderStrength(h.name, headerValues[h.name])])
    ),
  };
}
