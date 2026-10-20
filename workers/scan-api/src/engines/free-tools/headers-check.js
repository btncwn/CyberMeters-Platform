// ── Free security headers checker (public /tools/security-headers-checker) ──
//
// One GET of the site's home page over HTTPS, the same request a browser makes,
// through the scanner's SSRF-guarded safeFetch (every hop re-resolved and
// refused if it points at a private or reserved address). Only the response
// headers are read; the body is cancelled unread. Each header is judged by the
// scanner's own classifier (headers-scan.js classifyHeaderStrength) against the
// canonical header list (security-headers-config.js), so the free tool and the
// full scan can never disagree about what "weak" means.
//
// Honesty rules:
//  • No answer, a challenge page or an error page is "could not check", never
//    "headers missing": those responses do not carry the site's real headers.
//  • The ready-to-paste lines cover only what is missing or weak. A CSP is site
//    specific: a missing one gets a report-only starting point, said so; an
//    existing one with unsafe script sources gets advice on what to remove,
//    never a replacement that would throw away the site's own policy.
//  • Like the full scan, an unsafe style source alone is a note, not a problem
//    (classifyCspPolicy: style_only_weakness, actionable_weakness false).
import { classifyCspPolicy, classifyHeaderStrength } from "../headers-scan.js";
import { SECURITY_HEADERS } from "../security-headers-config.js";
import { safeFetch } from "../../lib/http.js";

export const HEADERS_TOOL_SCHEMA = "free-tool-headers.v1";

const VALUE_MAX = 300;

// What each header does for a small business, and the value we suggest when it
// is missing or weak. Header names and order follow SECURITY_HEADERS.
const GUIDE = Object.freeze({
  "strict-transport-security": {
    meaning: "Tells browsers to use HTTPS only, so a visitor cannot be quietly downgraded to an insecure connection.",
    suggest: "max-age=31536000; includeSubDomains",
    caution: "includeSubDomains applies to every subdomain: only add it when they all serve HTTPS. Add preload only after reading hstspreload.org, because it is hard to undo.",
  },
  "content-security-policy": {
    meaning: "Limits which scripts, styles and frames the page may load, which blunts injected scripts (XSS).",
    suggest: "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
    report_only: true,
    caution: "A policy has to match your site. The lines use the Report-Only header first: watch the browser console for what it would block, adjust, then rename it to Content-Security-Policy.",
  },
  "x-frame-options": {
    meaning: "Stops other sites showing your pages inside a frame, which is how clickjacking works.",
    suggest: "SAMEORIGIN",
  },
  "x-content-type-options": {
    meaning: "Stops browsers guessing a file's type, so an uploaded file cannot be run as a script.",
    suggest: "nosniff",
  },
  "referrer-policy": {
    meaning: "Controls how much of your page address is sent to other sites when visitors follow a link.",
    suggest: "strict-origin-when-cross-origin",
  },
  "permissions-policy": {
    meaning: "Switches off browser features your site does not use, such as the camera, microphone and location.",
    suggest: "camera=(), microphone=(), geolocation=()",
  },
});

const DISPLAY_NAME = Object.freeze({
  "strict-transport-security": "Strict-Transport-Security",
  "content-security-policy": "Content-Security-Policy",
  "x-frame-options": "X-Frame-Options",
  "x-content-type-options": "X-Content-Type-Options",
  "referrer-policy": "Referrer-Policy",
  "permissions-policy": "Permissions-Policy",
});

const NOT_CHECKED = Object.freeze([
  { label: "Other pages of the site", reason: "Only the home page was requested. Other pages, and your login or checkout pages, can send different headers." },
  { label: "Cookies", reason: "Cookie flags (Secure, HttpOnly, SameSite) are checked in the full scan." },
  { label: "The certificate and TLS versions", reason: "The full scan checks these." },
  { label: "Whether the CSP actually stops an attack", reason: "That depends on the whole policy and the page; we only flag the clearly unsafe parts." },
]);

const WHY_IT_MATTERS = "Security headers are instructions your website gives every visitor's browser. They cost nothing to add, and they close off common attacks: being downgraded to an insecure connection, having your pages framed by a fake site, or a malicious script running on your page.";

const CHALLENGE_URL = /challenges\.cloudflare\.com|\/captcha|consent\.google\.com|\/sorry\//i;

function clip(value) {
  const text = String(value ?? "");
  return text.length > VALUE_MAX ? `${text.slice(0, VALUE_MAX)}…` : text;
}

function headerMap(headers) {
  const out = {};
  if (!headers) return out;
  for (const [name, value] of headers.entries()) out[name.toLowerCase()] = value;
  return out;
}

/**
 * Why a response cannot speak for the site's headers, or null when it can.
 * A challenge page or an error page carries the edge's headers, not the site's.
 */
function unusableResponse(observation) {
  if (!observation) return "no_answer";
  const { status, final_url: finalUrl, headers } = observation;
  if ((headers["cf-mitigated"] || "").toLowerCase() === "challenge" || CHALLENGE_URL.test(finalUrl || "")) return "challenge";
  if (!Number.isInteger(status) || status >= 400) return "error_status";
  return null;
}

function judge(name, value) {
  if (value === undefined || value === null) return { status: "missing", details: "Not sent." };
  if (name === "content-security-policy") {
    const csp = classifyCspPolicy(value);
    if (csp.style_only_weakness) {
      return { status: "valid", details: "Set. style-src allows 'unsafe-inline', a minor risk the full scan also treats as a note.", note: true };
    }
    return { status: csp.status, details: csp.details, dangerous_directives: csp.dangerous_directives };
  }
  const strength = classifyHeaderStrength(name, value);
  return { status: strength.status, details: strength.details };
}

function snippets(lines) {
  if (lines.length === 0) return null;
  return {
    nginx: lines.map(({ name, value }) => `add_header ${name} "${value.replace(/"/g, '\\"')}" always;`).join("\n"),
    apache: lines.map(({ name, value }) => `Header always set ${name} "${value.replace(/"/g, '\\"')}"`).join("\n"),
    cloudflare: ["/*", ...lines.map(({ name, value }) => `  ${name}: ${value}`)].join("\n"),
  };
}

/**
 * The public result from one observation. Pure: no network.
 * observation = null (no answer) or { status, final_url, headers: { lower-name: value } }.
 */
export function buildHeadersToolResult(domain, observation, { now = Date.now() } = {}) {
  const base = { schema: HEADERS_TOOL_SCHEMA, tool: "headers", domain, checked_at: new Date(now).toISOString() };
  const unusable = unusableResponse(observation);
  if (unusable) {
    const why = {
      no_answer: `https://${domain} did not answer, or it points at an address we do not connect to.`,
      challenge: "The site answered with a bot check or consent page, which carries the protection service's headers rather than your site's.",
      error_status: `The site answered with an error (HTTP ${observation?.status}). Error pages often send different headers from real pages.`,
    }[unusable];
    return {
      ...base,
      verdict: { level: "unknown", headline: "Could not check the security headers", summary: `${why} Nothing was concluded about this site's headers.` },
      response: observation ? { status: observation.status, final_url: observation.final_url } : null,
      headers: [],
      checked: [{ label: "Home page over HTTPS", state: "unknown", detail: why }],
      not_checked: NOT_CHECKED,
      why_it_matters: WHY_IT_MATTERS,
      next_step: { title: "Try again shortly", explanation: "If your site normally loads in a browser, try again in a few minutes.", record: null, snippets: null },
    };
  }

  const values = observation.headers;
  const cspValue = values["content-security-policy"];
  const frameAncestors = typeof cspValue === "string" && /(^|;)\s*frame-ancestors\s/i.test(cspValue);
  const rows = SECURITY_HEADERS.map((entry) => {
    const value = values[entry.name];
    let verdict = judge(entry.name, value);
    // CSP frame-ancestors replaces X-Frame-Options in every current browser.
    if (entry.name === "x-frame-options" && verdict.status === "missing" && frameAncestors) {
      verdict = { status: "valid", details: "Not sent, but the CSP frame-ancestors directive does the same job." };
    }
    return {
      name: DISPLAY_NAME[entry.name],
      key: entry.name,
      label: entry.label,
      present: value !== undefined && value !== null,
      value: value === undefined || value === null ? null : clip(value),
      status: verdict.status,
      details: verdict.details,
      note: verdict.note === true,
      meaning: GUIDE[entry.name].meaning,
      dangerous_directives: verdict.dangerous_directives || [],
    };
  });

  const needsWork = rows.filter((row) => row.status === "missing" || row.status === "weak" || row.status === "malformed");
  // An existing CSP with unsafe script sources is tightened, not replaced.
  const cspToTighten = needsWork.find((row) => row.key === "content-security-policy" && row.present);
  const fixes = needsWork.filter((row) => row !== cspToTighten).map((row) => {
    const guide = GUIDE[row.key];
    return { name: guide.report_only ? "Content-Security-Policy-Report-Only" : row.name, value: guide.suggest, caution: guide.caution || null };
  });
  const advice = cspToTighten
    ? [`Your Content-Security-Policy allows unsafe script sources in ${cspToTighten.dangerous_directives.join(" and ") || "a script directive"}. Remove 'unsafe-inline', 'unsafe-eval' and * there, moving inline scripts into files or allowing them by nonce or hash. Keep the rest of your policy as it is.`]
    : [];
  const missingHsts = needsWork.some((row) => row.key === "strict-transport-security");
  const missingCount = rows.filter((row) => row.status === "missing").length;
  const weakCount = needsWork.length - missingCount;

  const level = needsWork.length === 0 ? "good" : (missingHsts || needsWork.length >= 3 ? "risk" : "attention");
  const parts = [];
  if (missingCount) parts.push(`${missingCount} missing`);
  if (weakCount) parts.push(`${weakCount} weak or invalid`);
  const verdict = needsWork.length === 0
    ? { level, headline: "All six security headers are set", summary: "The home page sends every header we check, with no weakness we can see." }
    : {
      level,
      headline: `${needsWork.length} of 6 security headers ${needsWork.length === 1 ? "needs" : "need"} attention`,
      summary: `${parts.join(", ")}${missingHsts ? ", including Strict-Transport-Security" : ""}. The lines below add or fix them.`,
    };

  const finalHost = (() => { try { return new URL(observation.final_url).hostname; } catch { return null; } })();
  const offSite = finalHost && finalHost !== domain && !finalHost.endsWith(`.${domain}`) && !domain.endsWith(`.${finalHost}`);
  const checked = [
    { label: "Home page over HTTPS", state: "pass", detail: `HTTP ${observation.status} from ${observation.final_url}` },
    ...(offSite ? [{ label: "Where the page came from", state: "warn", detail: `The address redirected to ${finalHost}, so these are that site's headers.` }] : []),
  ];

  return {
    ...base,
    verdict,
    response: { status: observation.status, final_url: observation.final_url },
    headers: rows,
    checked,
    not_checked: NOT_CHECKED,
    why_it_matters: WHY_IT_MATTERS,
    next_step: needsWork.length === 0
      ? { title: "No change needed", explanation: "Re-check after a site change or a move to a new host.", record: null, snippets: null }
      : {
        title: fixes.length === 0 ? "Tighten your Content-Security-Policy" : `Add ${fixes.length === 1 ? "this header" : "these headers"}`,
        explanation: fixes.length === 0
          ? "This needs a change to your existing policy rather than a new line."
          : "Paste the lines for your web server or host. They change only the headers, not the page.",
        record: null,
        headers: fixes,
        snippets: snippets(fixes),
        cautions: [...advice, ...fixes.map((fix) => fix.caution).filter(Boolean)],
      },
  };
}

async function observe(url, { accounting, signal, cache, dnsQuery, fetchImpl }) {
  const res = await safeFetch(url, {
    method: "GET",
    redirect: "follow",
    headers: { Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8" },
    accounting,
    signal,
    dnsResolver: dnsQuery,
    dnsCache: cache,
    ...(fetchImpl ? { fetchImpl } : {}),
  });
  if (!res) return null;
  try { await res.body?.cancel(); } catch { /* body is never read */ }
  return { status: res.status, final_url: res.url || url, headers: headerMap(res.headers) };
}

/** Run the check: the apex over HTTPS, then www. when the apex does not answer. */
export async function runHeadersCheck(domain, deps = {}) {
  let observation = await observe(`https://${domain}/`, deps);
  if (!observation && !domain.startsWith("www.")) observation = await observe(`https://www.${domain}/`, deps);
  return buildHeadersToolResult(domain, observation, { now: deps.now ? deps.now() : Date.now() });
}
