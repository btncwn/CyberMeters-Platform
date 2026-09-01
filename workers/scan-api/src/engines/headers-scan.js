// ── HTTP headers / bot-protection scan module ──
// Security-headers analysis (HSTS/CSP/XFO/etc. strength classification) + bot/edge
// protection detection, plus the runHeadersModule scan phase. Extracted verbatim from
// index.js (monolith decomposition, Phase 1c). Internal: BOT_CHALLENGE_URL_PATTERNS,
// HEADER_PROBE_INIT, detectBotProtection. classifyHeaderStrength is also used elsewhere.
import { safeFetch } from "../lib/http.js";
import { classifyFetchObservation, FETCH_OBSERVATION_STATES } from "../lib/fetch-observation.js";
import { SECURITY_HEADERS } from "./security-headers-config.js";

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
 *   CSP:                  directive-scoped; script/default danger is actionable, style-only danger is observational
 *   X-Frame-Options:      valid if DENY or SAMEORIGIN; malformed otherwise
 *   X-Content-Type-Options: valid if nosniff; malformed otherwise
 *   Referrer-Policy:      valid if strict value; weak if unsafe-url or no-referrer-when-downgrade
 *   Permissions-Policy:   valid if present (content-agnostic); unknown if cannot validate
 */
export function classifyCspPolicy(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    return {
      status: "unknown",
      classification: "unparseable",
      parsed: false,
      actionable_weakness: false,
      style_only_weakness: false,
      dangerous_directives: [],
      details: "CSP present but value is empty",
    };
  }

  const directives = new Map();
  for (const segment of raw.split(";")) {
    const parts = segment.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (parts.length === 0) continue;
    const [name, ...tokens] = parts;
    if (!/^[a-z][a-z0-9-]*$/.test(name)) {
      return {
        status: "malformed",
        classification: "unparseable",
        parsed: false,
        actionable_weakness: false,
        style_only_weakness: false,
        dangerous_directives: [],
        details: `CSP directive "${name}" is malformed`,
      };
    }
    // CSP applies the first occurrence of a directive. Mirroring that rule avoids
    // admitting a weakness from a duplicate directive the browser ignores.
    if (!directives.has(name)) directives.set(name, tokens);
  }
  if (directives.size === 0) {
    return {
      status: "unknown",
      classification: "unparseable",
      parsed: false,
      actionable_weakness: false,
      style_only_weakness: false,
      dangerous_directives: [],
      details: "CSP contains no parseable directives",
    };
  }

  const dangerous = new Set(["'unsafe-inline'", "'unsafe-eval'", "*"]);
  const dangerousTokens = (directive) =>
    (directives.get(directive) || []).filter((token) => dangerous.has(token));
  const scriptDanger = ["script-src", "default-src"]
    .map((directive) => ({ directive, tokens: dangerousTokens(directive) }))
    .filter((entry) => entry.tokens.length > 0);
  const styleDanger = dangerousTokens("style-src");

  if (scriptDanger.length > 0) {
    const dangerousDirectives = scriptDanger.map((entry) => entry.directive);
    return {
      status: "weak",
      classification: "weak_script",
      parsed: true,
      actionable_weakness: true,
      style_only_weakness: false,
      dangerous_directives: dangerousDirectives,
      details: `CSP contains dangerous source tokens in ${dangerousDirectives.join(" and ")}`,
    };
  }
  if (styleDanger.length > 0) {
    return {
      status: "weak",
      classification: "weak_style_only",
      parsed: true,
      actionable_weakness: false,
      style_only_weakness: true,
      dangerous_directives: ["style-src"],
      details: "CSP permits an unsafe style source but has no dangerous script-src/default-src token",
    };
  }
  return {
    status: "valid",
    classification: "no_admitted_weakness",
    parsed: true,
    actionable_weakness: false,
    style_only_weakness: false,
    dangerous_directives: [],
    details: "CSP present with no dangerous script-src or default-src token detected",
  };
}

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
    return classifyCspPolicy(value);
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

// ── Canonical response-header capture (detector + verifier share this) ────────
// The managed-verification profile must read HSTS and Set-Cookie from a re-observed
// response EXACTLY as the scan did, or a dse_hsts_* / dse_cookie_* case could be
// judged against different inputs than the finding was raised from. Both callers use
// these two helpers; neither re-implements the parsing.
export function securityHeaderValuesFrom(headers) {
  const values = {};
  for (const h of SECURITY_HEADERS) values[h.name] = headers.get(h.name) || null;
  return values;
}

// Workers supports getAll() because multiple Set-Cookie values can't be safely
// comma-joined; fall back to a newline split elsewhere.
export function captureSetCookieRaw(headers) {
  try {
    return typeof headers.getAll === "function"
      ? headers.getAll("set-cookie")
      : (headers.get("set-cookie") || "").split(/\r?\n/).filter(Boolean);
  } catch { return []; }
}

export async function runHeadersModule(domain, opts = {}) {
  const accounting = opts.accounting || null;
  // One redirect-following safeFetch may consume five valid 9,999ms attempts.
  // Queue/Cron supplies a runner-owned remainingMs carrier; callers without it
  // preserve the historical full-probe behaviour.
  const OPTIONAL_PROBE_ADMISSION_MS = 49_996;
  let optionalProbeBudgetExhausted = false;
  const canLaunchProbe = () => opts.signal?.aborted !== true;
  const canLaunchOptionalProbe = () => canLaunchProbe()
    && (typeof opts.remainingMs !== "function" || opts.remainingMs() >= OPTIONAL_PROBE_ADMISSION_MS);
  // Track B sub-operation timing — observational only, guarded at every call so a
  // broken/absent collector can never alter probe behaviour or the module result.
  // Each row times ONE safeFetch call end to end, including the redirect hops
  // safeFetch follows internally for redirect:"follow" — that whole call is what
  // consumes this module's 1.2s cap (SCAN_MODULE_BUDGETS.headers; ssl is 9s,
  // subdomains 12s with an inner 15s hard cap).
  // NEVER open a row once the module signal is aborted: after the cap fires the
  // loop can still fall through to the http protocol retry, but that probe never
  // truly begins — no row is the honest record for a non-event.
  const subOpBegin = (name) => {
    try {
      if (opts.signal?.aborted === true) return null;
      return opts.subOps?.begin?.("headers", name) ?? null;
    } catch { return null; }
  };
  const subOpFinish = (token, res) => {
    try {
      opts.subOps?.finish?.(token, {
        outcome: res ? "ok" : (opts.signal?.aborted === true ? "aborted" : "unavailable"),
        aborted: !res && opts.signal?.aborted === true,
      });
    } catch { /* observational only */ }
  };
  let headerValues         = {};
  let accessible           = false;
  // The last executed-but-non-origin observation (edge error / transport
  // unavailable), so the module can say WHY it has no origin evidence instead of
  // collapsing every cause into one reason. Null when no probe ever responded.
  let nonOriginObservation = null;
  // F-48: the last ORIGIN response that was an error status, i.e. the origin
  // answered but served no usable representation of the site. Deliberately a
  // different variable — and later a different reason — from the edge/transport
  // case above, because "the origin told us it is broken" and "we never reached
  // the origin" are different facts about the customer.
  let originErrorObservation = null;
  let statusCode           = null;
  let originalUrl          = null;
  let responseUrl          = null;
  let redirectCount        = 0;
  let setCookieRaw         = [];
  let botProtectionSignals = [];
  let rawHeaderSnapshot    = {};   // all response headers for diagnostics / bot detection
  const checkedPaths       = [];

  const recordUnexecutedOptional = (label, requestedUrl, method = "HEAD") => {
    optionalProbeBudgetExhausted = true;
    checkedPaths.push({
      label,
      requested_url: requestedUrl,
      method,
      status: "not_executed",
      reason: "module_budget_insufficient",
      final_url: null,
      status_code: null,
      redirect_chain: [],
      headers_observed: {},
    });
  };

  const snapshotHeaders = (headers) => {
    const out = {};
    headers.forEach((v, k) => { out[k.toLowerCase()] = v; });
    return out;
  };

  const securityHeaderValues = (headers) => securityHeaderValuesFrom(headers);

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
    if (!canLaunchProbe()) break;
    const probeUrl = `${proto}://${domain}`;

    // ── Step 1: GET (primary) ─────────────────────────────────────────────
    const getSubOp = subOpBegin(`probe_get_${proto}`);
    const getRes = await safeFetch(probeUrl, {
      method:   "GET",
      redirect: "follow",
      accounting,
      signal: opts.signal,
      dnsResolver: opts.dnsResolver,
      dnsCache: opts.dnsCache,
      ...HEADER_PROBE_INIT,
    });
    subOpFinish(getSubOp, getRes);
    if (!getRes) continue;

    // ── 52x/530: a Response object is not proof the ORIGIN answered ───────────
    // Item 11A's completeness criterion ("fetch-failed ≠ missing; 52x/530"). A
    // Cloudflare-synthesised edge failure IS a real Response with real headers,
    // so the previous `accessible = true` on any non-null result read the edge's
    // own error page as the customer's site: every security header came back
    // absent and landed in `missing`, sourced from an origin that never served
    // the site — the exact confusion this criterion exists to prevent.
    //
    // The decision is NOT made here. lib/fetch-observation.js already owns the
    // canonical predicate (status range AND `server: cloudflare`, both required)
    // and the completeness vocabulary; ssl-scan and asset-intel consume the same
    // one. This module now consumes it too rather than growing a second dialect.
    // No new meaning is assigned to any status code by this change.
    const getObservation = classifyFetchObservation({ response: getRes, executed: true });
    if (getObservation.state !== FETCH_OBSERVATION_STATES.ORIGIN_RESPONSE) {
      // Record WHAT we saw, then keep looking on the next protocol. Nothing from
      // an edge error may reach headerValues, present/missing or the strength map.
      nonOriginObservation = getObservation;
      checkedPaths.push({
        label:         "origin_not_observed",
        requested_url: probeUrl,
        method:        "GET",
        status:        getObservation.state,
        final_url:     getRes.url || probeUrl,
        status_code:   getRes.status ?? null,
        redirect_chain: [],
        headers_observed: {},
      });
      continue;
    }

    // ── F-48: an origin 5xx is an answer, but not a serviceable site ─────────
    // The origin genuinely responded — this is NOT the F-42 edge case and must
    // not be relabelled as one. But a 5xx carries no representation of the site,
    // so nothing about the customer's header posture can be assessed from it.
    //
    // scoring.js already knows this: every header finding is gated on
    // `status_code === 200`, so an error response yields no finding. The defect
    // was that the COMPLETENESS contract was never told the same thing — so the
    // scan graded `complete`, the resolver saw zero material website findings,
    // and a site returning 503 to every HTTPS probe was published
    // ASSESSED_HEALTHY. One contract knew; the other was not informed.
    //
    // Bounded to 5xx on purpose. A 200/301/403/404 is a real application answer
    // and its existing treatment is deliberately untouched: widening this to
    // `!== 200` would change healthy-origin behaviour, which is a different
    // decision and not this correction's to make.
    if (Number(getRes.status) >= 500) {
      originErrorObservation = {
        status_code: getRes.status,
        requested_url: probeUrl,
        final_url: getRes.url || probeUrl,
      };
      // Keep the observed status/URLs as diagnostics. The origin DID answer and
      // that fact is worth recording; what we refuse to do is treat it as a
      // serviceable observation. Dropping it lost real information —
      // validate-security-headers-binding.js caught exactly that, asserting the
      // module still reports `status_code === 503` for a 5xx. Recording it costs
      // nothing and keeps that contract true.
      statusCode  = getRes.status;
      originalUrl = probeUrl;
      responseUrl = getRes.url || probeUrl;
      checkedPaths.push({
        label:         "origin_error_response",
        requested_url: probeUrl,
        method:        "GET",
        status:        "origin_error",
        final_url:     getRes.url || probeUrl,
        status_code:   getRes.status ?? null,
        redirect_chain: [],
        headers_observed: {},
      });
      continue;
    }

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
    setCookieRaw = captureSetCookieRaw(getRes.headers);

    // ── Step 2: Bot protection detection ─────────────────────────────────
    botProtectionSignals = detectBotProtection(statusCode, responseUrl, rawHeaderSnapshot);

    if (botProtectionSignals.length > 0) {
      // GET was intercepted by an edge challenge.  Try HEAD — some WAFs skip
      // challenge injection on HEAD requests, potentially returning real headers.
      if (!canLaunchProbe()) break;
      if (!canLaunchOptionalProbe()) {
        recordUnexecutedOptional("bot_head_retry", probeUrl);
      } else {
        const headSubOp = subOpBegin("probe_head_bot_retry");
        const headRes = await safeFetch(probeUrl, {
          method:   "HEAD",
          redirect: "follow",
          accounting,
          signal: opts.signal,
          dnsResolver: opts.dnsResolver,
          dnsCache: opts.dnsCache,
          ...HEADER_PROBE_INIT,
        });
        subOpFinish(headSubOp, headRes);
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
    }

    if (!domain.startsWith("www.")) {
      const wwwUrl = `${proto}://www.${domain}`;
      if (!canLaunchProbe()) break;
      if (!canLaunchOptionalProbe()) {
        recordUnexecutedOptional("www_variant", wwwUrl);
      } else {
        const wwwSubOp = subOpBegin("probe_head_www");
        const wwwRes = await safeFetch(wwwUrl, {
          method:   "HEAD",
          redirect: "follow",
          accounting,
          signal: opts.signal,
          dnsResolver: opts.dnsResolver,
          dnsCache: opts.dnsCache,
          ...HEADER_PROBE_INIT,
        });
        subOpFinish(wwwSubOp, wwwRes);
        recordHeaderCheck("www_variant", wwwUrl, wwwRes, "HEAD");
      }
    }

    break;
  }

  // Whether the final response came over HTTPS.
  // HSTS is only meaningful on HTTPS — used in computeScore to avoid false positives
  // when we had to fall back to plain HTTP.
  const finalHttps = responseUrl ? responseUrl.startsWith("https://") : false;

  const present = SECURITY_HEADERS.filter((h) => !!headerValues[h.name]).map((h) => h.name);
  const missing = SECURITY_HEADERS.filter((h) => !headerValues[h.name]).map((h) => h.name);

  // ── Probe execution is EVIDENCE, and its absence must say so ────────────────
  // `accessible` is the existing authority gate consumed by scoring. It is false
  // when the loop above never got a response on EITHER protocol, and also when
  // the mandatory primary succeeded but an optional canonical-host probe was
  // intentionally not executed. The latter retains `primary_accessible`, raw
  // capture, present/values and checked-path diagnostics, but cannot turn a
  // single-host absence into a customer finding or remediation.
  //
  // Before this, the module returned that state as an ordinary success — no error,
  // no incomplete, no skipped — so buildScanQuality graded the scan `complete`,
  // moduleAssessed() said headers were assessed, no header finding was emitted
  // (scoring gates on `accessible`), and the eight-domain resolver concluded
  // Website Security was **assessed_healthy — "no material issue observed"**. A
  // site nobody could reach was reported as healthy. That is the exact failure the
  // platform's first rule forbids, and the exact failure probeAsset already fixed
  // for exposure evidence (`reachable: null` + `probe_status: "not_executed"`,
  // never `reachable: false`).
  //
  // `incomplete` is the canonical way to say "this module did not truly run".
  // buildScanQuality turns it into scan_quality `partial`, moduleAssessed() turns
  // it into evidence_insufficient, and moduleCompletionGate.canVerify("headers")
  // turns it into "cannot verify" — so an unexecuted probe can never resolve a
  // condition either. One flag, and every gate downstream fails closed.
  //
  // `present`/`missing` are deliberately left as they are. They are diagnostics
  // and remain useful evidence about the primary response. The authoritative
  // scoring gate is closed when the optional matrix is truncated; emptying
  // `missing` would instead let a caller read "0 missing headers = good".
  const probeExecuted = accessible === true;
  const evidenceAuthoritative = probeExecuted && !optionalProbeBudgetExhausted;

  // An executed probe that reached only a Cloudflare edge error is a DIFFERENT
  // fact from a probe that never got a response, and the customer-facing reason
  // must not collapse the two. Both are `incomplete` — neither can support a
  // header verdict — but only this one can say the request was answered by
  // something. The spread above is left exactly as it was so the existing
  // not-executed guard (and the source-pinned assertion that protects it) is
  // untouched; this refines the reason afterwards without weakening it.
  const originNotObserved = !probeExecuted && nonOriginObservation !== null;
  // F-48. Ordered AFTER originNotObserved in the return spread so that when both
  // happened (one protocol hit an edge error, the other a genuine 5xx) the
  // customer-facing reason names the origin error — the stronger, more specific
  // fact about their site. `incomplete: true` itself comes from the untouched
  // probeExecuted spread either way, so neither guard can be lost.
  const originErrored = !probeExecuted && originErrorObservation !== null;

  return {
    accessible: evidenceAuthoritative,
    ...(optionalProbeBudgetExhausted ? { primary_accessible: probeExecuted } : {}),
    ...(probeExecuted ? {} : {
      incomplete: true,
      incomplete_reason: "probe_not_executed",
    }),
    ...(originNotObserved ? {
      incomplete_reason: "origin_not_observed",
      header_observation: {
        state:          nonOriginObservation.state,
        reason:         nonOriginObservation.reason,
        completeness:   nonOriginObservation.completeness,
        probe_executed: nonOriginObservation.probe_executed,
      },
    } : {}),
    ...(originErrored ? {
      incomplete_reason: "origin_error_no_serviceable_response",
      header_observation: {
        state:          "origin_error_response",
        reason:         "origin_error_no_serviceable_response",
        completeness:   "incomplete",
        probe_executed: true,
        origin_status:  originErrorObservation.status_code,
      },
    } : {}),
    ...(!originNotObserved && !originErrored && optionalProbeBudgetExhausted ? {
      incomplete: true,
      incomplete_reason: "optional_probe_budget_exhausted",
    } : {}),
    headers_assessed:       evidenceAuthoritative,
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
