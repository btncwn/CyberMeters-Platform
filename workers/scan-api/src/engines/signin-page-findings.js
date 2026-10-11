// ── Website Security: findings from the site's own sign-in pages ────────────
//
// Turns page-discovery observations (engines/page-discovery.js) into canonical
// Website Security findings — but ONLY for pages that are sign-in pages by
// evidence (a password field was observed), never for a page that merely looks
// like one by its address. Four conditions:
//
//   https_signin_form_cross_origin — the password form sends to another site
//   https_signin_form_insecure     — the password form (or the page) uses plain HTTP
//   https_signin_no_hsts           — the homepage sends HSTS but a sign-in page does not
//   https_signin_cookie_no_secure  — a sign-in page sets a cookie without Secure over HTTPS
//
// Honesty (permanent):
//   • "detected" is not "malicious": a form posting to another site is reported
//     as exactly that, never as phishing or theft;
//   • absence proves a fix only when the sign-in pages were actually observed on a
//     scan whose page check was not cut short (evaluateSignInCondition → "clear");
//     anything else is "deferred" (unknown), never "fixed";
//   • evidence holds paths, hosts and cookie NAMES only — never values or HTML.

export const SIGNIN_CONDITION_KEYS = Object.freeze([
  "https_signin_form_cross_origin",
  "https_signin_form_insecure",
  "https_signin_no_hsts",
  "https_signin_cookie_no_secure",
]);
const KEYS = new Set(SIGNIN_CONDITION_KEYS);
export const isSignInConditionKey = (key) => KEYS.has(String(key || ""));

// Partial reasons that cannot hide a sign-in page: sensitive pages are fetched
// first, and the catch-all baseline only affects soft-404 detection.
const NON_BLOCKING_PARTIAL = new Set(["page_limit", "catch_all_baseline_unavailable"]);

const HSTS = "strict-transport-security";

/** Observed pages that are sign-in pages by evidence (a password field was seen). */
export function signInPages(discovery) {
  return (discovery?.pages || []).filter((p) => p?.outcome === "observed" && p.password_field === true);
}
function homepage(discovery) {
  return (discovery?.pages || []).find((p) => p?.source === "homepage" && p.outcome === "observed") || null;
}
const hasHsts = (p) => Array.isArray(p?.security_headers?.present) && p.security_headers.present.includes(HSTS);
const lacksHsts = (p) => Array.isArray(p?.security_headers?.missing) && p.security_headers.missing.includes(HSTS);

const PREDICATES = Object.freeze({
  https_signin_form_cross_origin: (p) => (p.forms || []).some((f) => f.has_password && f.action_kind === "other_origin"),
  https_signin_form_insecure: (p) => p.https === false || (p.forms || []).some((f) => f.has_password && f.action_scheme === "http"),
  // Only meaningful when the homepage DOES send HSTS (otherwise the site-wide
  // header_missing_strict_transport_security condition already says it).
  https_signin_no_hsts: (p, ctx) => ctx.homeHsts && p.https === true && lacksHsts(p),
  https_signin_cookie_no_secure: (p) => p.https === true && (p.cookies || []).some((c) => c && c.secure === false),
});

/**
 * evaluateSignInCondition(key, discovery) → { state: "present" | "clear" | "deferred", reason }
 * clear: sign-in pages were observed on a page check that was not cut short, and
 * the predicate is false on every one of them (and, for HSTS, the homepage still
 * sends HSTS). Everything else that is not present is deferred — never "fixed".
 */
export function evaluateSignInCondition(key, discovery) {
  const pred = PREDICATES[key];
  if (!pred) return { state: "deferred", reason: "unknown_condition" };
  if (!discovery || discovery.source !== "page_discovery" || discovery.coverage === "not_run") return { state: "deferred", reason: "page_check_not_run" };
  const pages = signInPages(discovery);
  const home = homepage(discovery);
  const ctx = { homeHsts: hasHsts(home) };
  if (pages.some((p) => pred(p, ctx))) return { state: "present", reason: "observed_on_sign_in_page" };
  if (!pages.length) return { state: "deferred", reason: "no_sign_in_page_observed" };
  const blocking = (discovery.partial_reasons || []).filter((r) => !NON_BLOCKING_PARTIAL.has(r));
  if (discovery.coverage !== "complete" && blocking.length) return { state: "deferred", reason: "page_check_partial" };
  if (key === "https_signin_no_hsts" && !ctx.homeHsts) return { state: "deferred", reason: "homepage_hsts_not_observed" };
  // Zero cookies proves nothing about cookie flags (the same rule as the homepage cookie checks).
  if (key === "https_signin_cookie_no_secure" && !pages.some((p) => p.https === true && (p.cookies || []).length > 0)) return { state: "deferred", reason: "no_cookie_observed" };
  return { state: "clear", reason: "sign_in_pages_observed_and_clear" };
}

const TITLES = {
  https_signin_form_cross_origin: "Sign-in form sends passwords to another site",
  https_signin_form_insecure: "Sign-in form sends passwords over plain HTTP",
  https_signin_no_hsts: "Sign-in page is served without HSTS",
  https_signin_cookie_no_secure: "Sign-in page sets a cookie without Secure",
};
const SEVERITY = {
  https_signin_form_cross_origin: "medium",
  https_signin_form_insecure: "high",
  https_signin_no_hsts: "medium",
  https_signin_cookie_no_secure: "medium",
};

function describe(key, pages, ctx) {
  const paths = pages.map((p) => p.path).slice(0, 5);
  const list = paths.join(", ");
  if (key === "https_signin_form_cross_origin") {
    const hosts = [...new Set(pages.flatMap((p) => (p.forms || []).filter((f) => f.has_password && f.action_kind === "other_origin").map((f) => f.action_host)).filter(Boolean))].slice(0, 5);
    return { text: `The password form on ${list} sends to ${hosts.join(", ") || "another site"}. Passwords typed there leave this site.`, observed: { hosts } };
  }
  if (key === "https_signin_form_insecure") return { text: `The password form on ${list} is served or sent over plain HTTP, so passwords can travel unencrypted.`, observed: {} };
  if (key === "https_signin_no_hsts") return { text: `The homepage sends Strict-Transport-Security but ${list} does not, so browsers are not told to keep the sign-in page on HTTPS.`, observed: { homepage_hsts: ctx.homeHsts } };
  const names = [...new Set(pages.flatMap((p) => (p.cookies || []).filter((c) => c && c.secure === false).map((c) => c.name)))].slice(0, 5);
  return { text: `${list} sets ${names.join(", ") || "a cookie"} without the Secure attribute, so the cookie can also be sent over plain HTTP.`, observed: { cookie_names: names } };
}

/** Findings for this scan (one per condition at most). Empty when the page check did not run. */
export function signInPageFindings(discovery, { domain = null, checkedAt = new Date().toISOString() } = {}) {
  if (!discovery || discovery.source !== "page_discovery" || discovery.coverage === "not_run") return [];
  const pages = signInPages(discovery);
  if (!pages.length) return [];
  const ctx = { homeHsts: hasHsts(homepage(discovery)) };
  const out = [];
  for (const key of SIGNIN_CONDITION_KEYS) {
    const hit = pages.filter((p) => PREDICATES[key](p, ctx));
    if (!hit.length) continue;
    const { text, observed } = describe(key, hit, ctx);
    out.push({
      id: key,
      module: "page_discovery",
      finding_type: "finding",
      severity: SEVERITY[key],
      confidence: "high",
      title: TITLES[key],
      description: text,
      score_impact: 0,
      evidence: {
        evidence_type: "http_header_probe",
        probe_target: domain,
        requested_url: hit[0].requested_url ? String(hit[0].requested_url).split("?")[0] : null,
        final_url: hit[0].final_url || null,
        observed_value: { sign_in_paths: hit.map((p) => p.path).slice(0, 5), ...observed },
        expected_value: key === "https_signin_form_cross_origin" ? "password forms post to this site"
          : key === "https_signin_form_insecure" ? "password forms served and sent over HTTPS"
          : key === "https_signin_no_hsts" ? "Strict-Transport-Security on sign-in pages"
          : "Secure on cookies set by sign-in pages",
        source: "page_discovery",
        checked_at: checkedAt,
      },
    });
  }
  return out;
}
