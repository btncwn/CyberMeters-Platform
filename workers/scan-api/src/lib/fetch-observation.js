// ─────────────────────────────────────────────────────────────────────────────
// Shared Workers-fetch observation classifier.
//
// One place decides what a `fetch()` result from inside a Cloudflare Worker
// actually OBSERVED. Three distinct facts used to collapse into one boolean:
//
//   1. an HTTP response genuinely produced by the customer's origin;
//   2. a Cloudflare-synthesised edge failure — a real Response object, but no
//      origin ever answered;
//   3. transport that could not be observed at all (timeout, refusal, block),
//      or a probe that never ran.
//
// Collapsing (2) and (3) into "false" is how a domain serving valid TLS earned a
// CRITICAL "HTTPS Not Available" finding telling its owner to install a
// certificate. Absent evidence is not a security verdict.
//
// TWO RULES THIS MODULE EXISTS TO ENFORCE
//
//   A. ANY origin HTTP status — 1xx, 2xx, 3xx, 4xx AND 5xx — proves HTTPS
//      transport. To return a status over https:// the TLS handshake completed
//      and a certificate was presented and accepted. A genuine origin 500 is an
//      application-health fact; it is NEVER certificate absence, never
//      "traffic is transmitted unencrypted", never "install a certificate".
//      (The historical `status < 500` rule was wrong for this reason alone,
//      independently of the Cloudflare-edge issue.)
//
//   B. "Executed but inconclusive" and "never looked" are different states and
//      must not be collapsed into a bare null. Callers get an explicit state and
//      reason alongside the tri-state boolean so a consumer can tell an edge
//      error from a probe that never ran.
//
// The certificate/TLS evidence family is deliberately NOT decided here: a
// Workers `fetch()` cannot observe the peer chain, hostname match, stapled OCSP
// or trust store, so this module never emits certificate absence or validity.
// It classifies TRANSPORT OBSERVATION only.
// ─────────────────────────────────────────────────────────────────────────────

// Cloudflare-edge error statuses: 520–527 (origin connection/response failures)
// and 530 (carries a 1xxx code, incl. 1016 origin DNS error). These are
// synthesised by the Cloudflare edge when NO origin produced an HTTP answer —
// they are never an origin's own response.
//
// The `Server: cloudflare` signature is REQUIRED alongside the status range: a
// proxied origin's own 5xx keeps its real status (500/502/503…, outside this
// range), and a non-Cloudflare host emitting a non-standard 52x without the
// signature must stay in the stricter server-error reading rather than being
// excused as an edge artefact.
export const CF_EDGE_STATUS_MIN = 520;
export const CF_EDGE_STATUS_MAX = 530;

// Canonical observation vocabulary. Values reuse the platform's existing words
// (observed / unavailable / incomplete / not_assessed) so a consumer that
// already speaks coverage-state does not learn a second dialect.
export const FETCH_OBSERVATION_STATES = Object.freeze({
  ORIGIN_RESPONSE:       "origin_response",
  CLOUDFLARE_EDGE_ERROR: "cloudflare_edge_error",
  TRANSPORT_UNAVAILABLE: "transport_unavailable",
  NOT_ASSESSED:          "not_assessed",
});

// Evidence-completeness class each state maps to, in the platform's existing
// coverage vocabulary. `incomplete` is the honest reading of an edge error: the
// probe DID execute and did observe something real about the edge, but nothing
// attributable to the customer's origin.
export const FETCH_OBSERVATION_COMPLETENESS = Object.freeze({
  [FETCH_OBSERVATION_STATES.ORIGIN_RESPONSE]:       "observed",
  [FETCH_OBSERVATION_STATES.CLOUDFLARE_EDGE_ERROR]: "incomplete",
  [FETCH_OBSERVATION_STATES.TRANSPORT_UNAVAILABLE]: "unavailable",
  [FETCH_OBSERVATION_STATES.NOT_ASSESSED]:          "not_assessed",
});

/**
 * True when a status+server pair is a Cloudflare-synthesised edge failure rather
 * than an origin's own response. Both the status range AND the edge signature
 * are required — see the constant comments above.
 */
export function isCloudflareEdgeSynthesised(status, server) {
  const code = Number(status);
  if (!Number.isFinite(code)) return false;
  return code >= CF_EDGE_STATUS_MIN && code <= CF_EDGE_STATUS_MAX &&
    String(server || "").trim().toLowerCase() === "cloudflare";
}

/** Read a header off a Response-like object without assuming a Headers impl. */
function headerOf(response, name) {
  const get = response?.headers?.get;
  if (typeof get !== "function") return null;
  try { return response.headers.get(name); } catch { return null; }
}

/**
 * classifyFetchObservation({ response, executed, failure })
 *
 * The single decision point. Returns:
 *   {
 *     state,             // FETCH_OBSERVATION_STATES
 *     reason,            // stable machine token, safe to persist and to render
 *     completeness,      // FETCH_OBSERVATION_COMPLETENESS for the state
 *     probe_executed,    // did we actually attempt the request?
 *     transport_observed,// true | null — NEVER false from a fetch result alone
 *     origin_status,     // number | null — present only for a genuine origin response
 *   }
 *
 * `transport_observed` is deliberately true-or-null. A Workers fetch can PROVE
 * transport (an origin answered) but can never prove its ABSENCE: a timeout, a
 * reset, an SSRF block and an edge error are all "we did not observe", not "the
 * customer has no HTTPS". Proving absence needs TLS/certificate evidence, which
 * belongs to a different signal family and a different module.
 *
 * @param {object}  args
 * @param {Response|null} args.response  the fetch result, or null when none came back
 * @param {boolean} args.executed        whether the probe was attempted at all
 * @param {string|null} args.failure     optional machine token for WHY no response
 *                                       (e.g. "timeout", "ssrf_blocked", "budget_exhausted")
 */
export function classifyFetchObservation({ response = null, executed = true, failure = null } = {}) {
  if (!executed) {
    return {
      state:              FETCH_OBSERVATION_STATES.NOT_ASSESSED,
      reason:             failure || "probe_not_executed",
      completeness:       FETCH_OBSERVATION_COMPLETENESS[FETCH_OBSERVATION_STATES.NOT_ASSESSED],
      probe_executed:     false,
      transport_observed: null,
      origin_status:      null,
    };
  }

  const status = Number(response?.status);
  if (!response || !Number.isFinite(status)) {
    // The probe ran and produced nothing usable: timeout, reset, refusal, block.
    // Executed-but-inconclusive — explicitly NOT the same as never looking.
    return {
      state:              FETCH_OBSERVATION_STATES.TRANSPORT_UNAVAILABLE,
      reason:             failure || "no_response_observed",
      completeness:       FETCH_OBSERVATION_COMPLETENESS[FETCH_OBSERVATION_STATES.TRANSPORT_UNAVAILABLE],
      probe_executed:     true,
      transport_observed: null,
      origin_status:      null,
    };
  }

  if (isCloudflareEdgeSynthesised(status, headerOf(response, "server"))) {
    // A real Response object, but the Cloudflare edge wrote it because no origin
    // answered. Nothing here is attributable to the customer's origin, so it can
    // support neither a health verdict nor an absence verdict.
    return {
      state:              FETCH_OBSERVATION_STATES.CLOUDFLARE_EDGE_ERROR,
      reason:             "cloudflare_edge_error",
      completeness:       FETCH_OBSERVATION_COMPLETENESS[FETCH_OBSERVATION_STATES.CLOUDFLARE_EDGE_ERROR],
      probe_executed:     true,
      transport_observed: null,
      origin_status:      null,
    };
  }

  // Rule A: any origin status proves transport, including 5xx.
  return {
    state:              FETCH_OBSERVATION_STATES.ORIGIN_RESPONSE,
    reason:             "origin_response",
    completeness:       FETCH_OBSERVATION_COMPLETENESS[FETCH_OBSERVATION_STATES.ORIGIN_RESPONSE],
    probe_executed:     true,
    transport_observed: true,
    origin_status:      status,
  };
}

/**
 * Legacy-shaped adapter for asset-intel's exposure probe, which asks the
 * narrower question "this host answered 5xx — was that the origin or the edge?"
 * Behaviour is byte-identical to the classifier it replaced; it now delegates so
 * there is exactly ONE definition of the Cloudflare-edge rule in the codebase.
 */
export function classifyServerErrorStatus(status, server) {
  if (isCloudflareEdgeSynthesised(status, server)) {
    // Authoritative negative — nothing serves at this name (same evidence class
    // as a refused connection). Distinct marker so consumers can still see WHY,
    // but never counted "not assessed": the probe DID complete and observed the
    // public truth.
    return { probe_status: "origin_unreachable", reason: "cloudflare_edge_error" };
  }
  // Genuine origin 5xx — answered, not content-assessable (per the #185 contract
  // this must never confirm absence or health, so it stays not-assessed).
  return { probe_status: "server_error", reason: "server_error" };
}
