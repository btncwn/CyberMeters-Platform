// ── Canonical cookie-attribute observation contract ─────────────────────────
// One pure contract shared by detection, Website Security lifecycle evaluation,
// and managed verification. It answers whether a specific canonical cookie
// condition is present, conclusively clear, or unknowable from this observation.
//
// A response that sets no cookies is never proof that cookie attributes were fixed:
// it may simply be a path/state that did not emit them. Callers must preserve the
// deferred state and its reason rather than translating absence into recovery.

export const COOKIE_FINDING_TYPES = Object.freeze([
  "dse_cookie_no_secure",
  "dse_cookie_no_httponly",
  "dse_cookie_no_samesite",
]);

const COOKIE_FINDING_SET = new Set(COOKIE_FINDING_TYPES);
const COOKIE_COUNTER = Object.freeze({
  dse_cookie_no_secure: "insecure_count",
  dse_cookie_no_httponly: "no_httponly",
  dse_cookie_no_samesite: "no_samesite",
});

export function isCookieFindingType(findingId) {
  return COOKIE_FINDING_SET.has(String(findingId || ""));
}

export function cookieEvidenceUsable(enrich) {
  const cookies = enrich?.cookies;
  return Boolean(cookies && !cookies.error)
    && Number.isFinite(cookies.found) && cookies.found >= 0
    && COOKIE_FINDING_TYPES.every((id) => {
      const value = cookies[COOKIE_COUNTER[id]];
      return Number.isFinite(value) && value >= 0;
    });
}

export function evaluateCookieObservation(findingId, enrich, { moduleComplete = false } = {}) {
  const id = String(findingId || "");
  if (!isCookieFindingType(id)) {
    return { state: "deferred", present: null, reason: "unsupported_cookie_finding" };
  }
  if (moduleComplete !== true || !enrich || enrich.error) {
    return { state: "deferred", present: null, reason: "module_not_assessed" };
  }
  if (!cookieEvidenceUsable(enrich)) {
    return { state: "deferred", present: null, reason: "cookie_evidence_unusable" };
  }
  if (enrich.cookies.found === 0) {
    return { state: "deferred", present: null, reason: "no_cookies_observed" };
  }
  const present = enrich.cookies[COOKIE_COUNTER[id]] > 0;
  return {
    state: present ? "present" : "clear",
    present,
    reason: present ? "canonical_cookie_predicate_true" : "canonical_cookie_predicate_false",
  };
}

export function cookieFindingPresent(findingId, enrich) {
  return evaluateCookieObservation(findingId, enrich, {
    moduleComplete: Boolean(enrich && !enrich.error),
  }).state === "present";
}
