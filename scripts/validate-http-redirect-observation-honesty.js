#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-http-redirect-observation-honesty.js  (CI-blocking)
//
// PR-A2 — HTTP Redirect Observation Honesty.
//
// THE HARM. `ssl-scan.js` set `http_redirect_validated = true` whenever the
// http:// probe returned a non-null Response. A Cloudflare-synthesised 520–527/530
// IS a non-null Response, so the chain was marked *validated* on evidence that
// never reached the customer's origin, and `scoring.js` then took its DEFINITIVE
// branch:
//
//     "HTTP Does Not Redirect to HTTPS"  ·  medium  ·  score_impact -5
//
// a verdict about a server nobody ever spoke to. Same root class as PR-A1, one
// field over: probe execution read as evidence completion.
//
// Sections: A initial hop · B second hop · C genuine behaviour preserved ·
// D scoring projection · E canonical incompleteness. Deterministic fixtures, real
// modules, mock fetch — no live D1/R2/network. Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENG = path.join(ROOT, "workers", "scan-api", "src", "engines");
const { runSslModule } = await import(pathToFileURL(path.join(ENG, "ssl-scan.js")).href);
const { computeScore } = await import(pathToFileURL(path.join(ENG, "scoring.js")).href);

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "ok  " : "FAIL"} - ${name}${!cond && detail ? ` -- ${detail}` : ""}`);
};

const realFetch = globalThis.fetch;
const noCt = { get: async () => null, set: async () => {} };

// ── fixture builders ────────────────────────────────────────────────────────
const edge = (status) => new Response("edge error", {
  status, headers: { server: "cloudflare", "content-type": "text/html" },
});
const originRedirect = (status, location) => new Response("", {
  status, headers: { location, server: "nginx" },
});
const originPlain = (status) => new Response("<html></html>", {
  status, headers: { server: "nginx", "content-type": "text/html" },
});

/**
 * Drive the REAL ssl module. `https` decides what https:// answers; `http` is a
 * function of the requested URL so a two-hop chain can be expressed exactly.
 */
async function sslWith({ https = () => originPlain(200), http }) {
  globalThis.fetch = async (input) => {
    const url = new URL(String(input));
    if (url.protocol === "https:") return https(url);
    return http(url);
  };
  const err = console.error; console.error = () => {};
  try { return await runSslModule("example.com", { ctCache: noCt }); }
  finally { globalThis.fetch = realFetch; console.error = err; }
}

const scoreOf = (ssl) => computeScore({ ssl, headers: { headers: {} }, dns: {}, email_security: {} }, "example.com");
const findingOf = (ssl) => (scoreOf(ssl).findings || []).find((f) => f.id === "ssl_no_http_redirect") || null;

// ── A. INITIAL HOP ───────────────────────────────────────────────────────────
console.log("\n── A. initial hop classification ──");
for (const status of [520, 522, 527, 530]) {
  const m = await sslWith({ http: () => edge(status) });
  const c = m.http_redirect_chain;
  ok(`A: Cloudflare-signed ${status} does NOT set http_redirect_validated`,
    c.http_redirect_validated === false, JSON.stringify(c.http_redirect_validated));
  ok(`A: …and records the edge observation honestly`,
    c.observation_state === "cloudflare_edge_error" &&
    c.observation_completeness === "incomplete", JSON.stringify(c.observation_state));
  ok(`A: …with bounded hop provenance (1 hop)`,
    Array.isArray(c.hop_observations) && c.hop_observations.length === 1 &&
    c.hop_observations[0].hop === 1 && c.hop_observations[0].state === "cloudflare_edge_error",
    JSON.stringify(c.hop_observations));
}
// The two statuses PR-A1 narrowed OUT of the edge set are genuine origin answers.
for (const status of [528, 529]) {
  const m = await sslWith({ http: () => edge(status) });
  ok(`A: signed ${status} is a GENUINE origin answer → validated`,
    m.http_redirect_chain.http_redirect_validated === true &&
    m.http_redirect_chain.observation_state === "origin_response");
}
{
  const m = await sslWith({ http: () => { throw new TypeError("timeout"); } });
  ok("A: a timeout leaves the chain unvalidated (unchanged behaviour)",
    m.http_redirect_chain.http_redirect_validated === false &&
    m.http_redirect_chain.observation_state === "transport_unavailable");
}

// ── B. SECOND HOP ────────────────────────────────────────────────────────────
console.log("\n── B. second hop classification ──");
{
  // http → http (hop 1 genuine) → hop 2 is a Cloudflare edge error. The chain has
  // NOT been observed to reach HTTPS and must not be read as if it had.
  const m = await sslWith({
    http: (url) => url.hostname === "example.com"
      ? originRedirect(301, "http://www.example.com/")
      : edge(522),
  });
  const c = m.http_redirect_chain;
  ok("B: hop-2 edge error does NOT produce an https redirect verdict",
    m.http_redirects_to_https === false, String(m.http_redirects_to_https));
  ok("B: hop-2 provenance is recorded (2 bounded hops)",
    c.hop_observations.length === 2 &&
    c.hop_observations[1].hop === 2 &&
    c.hop_observations[1].state === "cloudflare_edge_error",
    JSON.stringify(c.hop_observations));
  ok("B: hop-1 remains a genuine origin_response in provenance",
    c.hop_observations[0].state === "origin_response" &&
    c.hop_observations[0].origin_status === 301);
}
{
  // Genuine two-hop chain http → http → https must STILL validate.
  const m = await sslWith({
    http: (url) => url.hostname === "example.com"
      ? originRedirect(301, "http://www.example.com/")
      : originRedirect(301, "https://www.example.com/"),
  });
  ok("B: genuine http→http→https chain still resolves to a redirect (preserved)",
    m.http_redirects_to_https === true &&
    m.http_redirect_chain.redirect_count === 2 &&
    m.http_redirect_chain.http_redirect_validated === true,
    JSON.stringify(m.http_redirect_chain));
}

// ── B2. SEQUENTIAL CONTRACT — a required later hop can never be rescued ──────
// The bare/www aggregate rule (any origin response wins) is correct for two
// INDEPENDENT endpoints and WRONG here: hop 2 is a DEPENDENCY, so hop 1 answering
// says nothing about it. Previously hop 1's origin_response set the chain state and
// the module completeness, so a genuine 301 into a Cloudflare-signed 522 published
// the definitive medium -5 verdict with the required hop unobserved.
console.log("\n── B2. sequential second-hop contract ──");
{
  const m = await sslWith({
    https: () => originPlain(200),
    http: (url) => url.hostname === "example.com"
      ? originRedirect(301, "http://www.example.com/")
      : edge(522),                       // required hop 2: edge error, NO Location
  });
  const c = m.http_redirect_chain;
  ok("B2: chain validation is FALSE (hop 1 does not rescue hop 2)",
    c.http_redirect_validated === false, String(c.http_redirect_validated));
  ok("B2: CHAIN-level state is the failing hop's, not hop 1's origin_response",
    c.observation_state === "cloudflare_edge_error" &&
    c.observation_completeness === "incomplete", JSON.stringify(c.observation_state));
  ok("B2: hop 1 provenance still shows its genuine origin_response",
    c.hop_observations[0].state === "origin_response" && c.hop_observations.length === 2);
  ok("B2: module is incomplete via the canonical contract",
    m.incomplete === true && m.incomplete_reason === "http_redirect_not_observed",
    JSON.stringify({ i: m.incomplete, r: m.incomplete_reason }));
  const f = findingOf(m);
  ok("B2: NO definitive redirect verdict", !f || f.severity !== "medium", JSON.stringify(f && f.severity));
  ok("B2: NO score impact", !f || Number(f.score_impact || 0) === 0, JSON.stringify(f?.score_impact));
}
{
  // Hop 2 times out — same sequential rule, different inconclusive state.
  const m = await sslWith({
    https: () => originPlain(200),
    http: (url) => { if (url.hostname !== "example.com") throw new TypeError("hop2 timeout");
      return originRedirect(301, "http://www.example.com/"); },
  });
  ok("B2: hop-2 timeout also invalidates the chain",
    m.http_redirect_chain.http_redirect_validated === false &&
    m.http_redirect_chain.observation_state === "transport_unavailable" &&
    m.incomplete === true, JSON.stringify(m.http_redirect_chain.observation_state));
}
{
  // Hop 2 IS observed and simply does not redirect to https → fully observed chain,
  // so the definitive finding is legitimately sayable.
  const m = await sslWith({
    https: () => originPlain(200),
    http: (url) => url.hostname === "example.com"
      ? originRedirect(301, "http://www.example.com/")
      : originPlain(200),
  });
  ok("B2: observed hop 2 without an https redirect → chain observed, module complete",
    m.http_redirect_chain.http_redirect_validated === true && m.incomplete !== true);
  const f = findingOf(m);
  ok("B2: …and the definitive finding IS sayable (positive control)",
    !!f && f.severity === "medium" && Number(f.score_impact) === -5,
    JSON.stringify(f && { s: f.severity, i: f.score_impact }));
}

// ── L. LEGACY / MISSING-FIELD MATRIX — absence is never consent ───────────────
console.log("\n── L. legacy / missing-field matrix ──");
const definitive = (ssl) => {
  const f = findingOf(ssl);
  return !!f && f.severity === "medium" && Number(f.score_impact) === -5;
};
{
  // The ONLY case that may stay definitive: an old report with an explicit true.
  ok("L: legacy explicit http_redirect_validated=true MAY remain definitive",
    definitive({ https_available: null, http_redirect_chain: { http_redirect_validated: true } }));
  ok("L: legacy explicit false is NOT definitive",
    !definitive({ https_available: null, http_redirect_chain: { http_redirect_validated: false } }));
  ok("L: MISSING FIELD is NOT definitive (was `!== false` → true)",
    !definitive({ https_available: null, http_redirect_chain: { original_url: "http://example.com" } }));
  ok("L: ABSENT CHAIN is NOT definitive — PR-A1's deadline fallback shape",
    !definitive({ https_available: null, https_probe_executed: false, incomplete: true }));
  ok("L: absent ssl module entirely is NOT definitive", !definitive(undefined));
  for (const state of ["cloudflare_edge_error", "transport_unavailable", "not_assessed"]) {
    ok(`L: observation_state ${state} is NOT definitive`,
      !definitive({ https_available: null, http_redirect_chain: { http_redirect_validated: true, observation_state: state } }),
      "an explicit state must override a stale legacy boolean");
  }
  ok("L: observation_state origin_response IS definitive (positive control)",
    definitive({ https_available: null, http_redirect_chain: { http_redirect_validated: false, observation_state: "origin_response" } }));
}

// ── C. GENUINE BEHAVIOUR PRESERVED ───────────────────────────────────────────
console.log("\n── C. genuine origin behaviour preserved ──");
{
  const m = await sslWith({ http: () => originRedirect(301, "https://example.com/") });
  ok("C: real origin HTTP→HTTPS redirect remains validated",
    m.http_redirects_to_https === true && m.http_redirect_chain.http_redirect_validated === true);
  ok("C: …and the module is NOT marked incomplete", m.incomplete !== true, JSON.stringify(m.incomplete_reason));
}
{
  // A genuine origin 5xx must stay DISTINGUISHABLE from a Cloudflare edge response.
  const edgeM   = await sslWith({ http: () => edge(522) });
  const originM = await sslWith({ http: () => originPlain(503) });
  ok("C: genuine origin 503 IS validated evidence (the origin answered)",
    originM.http_redirect_chain.http_redirect_validated === true &&
    originM.http_redirect_chain.observation_state === "origin_response");
  ok("C: Cloudflare 522 is NOT — the two remain distinguishable",
    edgeM.http_redirect_chain.http_redirect_validated === false &&
    edgeM.http_redirect_chain.observation_state === "cloudflare_edge_error");
}

// ── D. SCORING PROJECTION ────────────────────────────────────────────────────
console.log("\n── D. customer-visible scoring projection ──");
{
  // THE REPORTED HARM: https unreachable (edge) + http edge → previously the
  // definitive medium -5 "HTTP Does Not Redirect to HTTPS".
  const m = await sslWith({ https: () => edge(522), http: () => edge(522) });
  const f = findingOf(m);
  ok("D: edge evidence NEVER yields the definitive medium redirect verdict",
    !f || (f.severity !== "medium" && f.title !== "HTTP Does Not Redirect to HTTPS"),
    JSON.stringify(f && { s: f.severity, t: f.title }));
  ok("D: edge evidence NEVER carries a redirect score impact",
    !f || Number(f.score_impact || 0) === 0, JSON.stringify(f?.score_impact));
}
{
  // POSITIVE CONTROL — a real origin that genuinely does not redirect must STILL
  // produce the existing definitive finding. This proves a scoped fix, not a
  // deleted check.
  const m = await sslWith({ https: () => originPlain(200), http: () => originPlain(200) });
  const f = findingOf(m);
  ok("D: POSITIVE CONTROL — genuine origin, no redirect → definitive medium finding STILL fires",
    !!f && f.severity === "medium" && f.title === "HTTP Does Not Redirect to HTTPS" &&
    Number(f.score_impact) === -5,
    JSON.stringify(f && { s: f.severity, t: f.title, i: f.score_impact }));
}
{
  const m = await sslWith({ https: () => originPlain(200), http: () => originRedirect(301, "https://example.com/") });
  ok("D: a genuine redirect produces NO redirect finding at all",
    findingOf(m) === null);
}
{
  // A missing observation_state (legacy report) must not silently become definitive.
  const legacyUnvalidated = { https_available: null, http_redirect_chain: { http_redirect_validated: false } };
  const f = findingOf(legacyUnvalidated);
  ok("D: legacy chain with validated=false stays non-definitive",
    !f || Number(f.score_impact || 0) === 0, JSON.stringify(f?.severity));
}

// ── E. CANONICAL INCOMPLETENESS ──────────────────────────────────────────────
console.log("\n── E. canonical module incompleteness ──");
{
  // HTTPS observed fine, but the redirect evidence never reached the origin. The
  // verdict is withheld — and a withheld verdict must not read as a FIXED redirect,
  // so the module reports incompleteness through the CANONICAL contract.
  const m = await sslWith({ https: () => originPlain(200), http: () => edge(522) });
  ok("E: redirect-only gap marks the module incomplete via the canonical contract",
    m.incomplete === true && m.incomplete_reason === "http_redirect_not_observed",
    JSON.stringify({ i: m.incomplete, r: m.incomplete_reason }));
  ok("E: …while the HTTPS signal itself stays positively observed",
    m.https_available === true);
}
{
  // When BOTH are unobserved the HTTPS reason wins — it is the more fundamental gap.
  const m = await sslWith({ https: () => edge(522), http: () => edge(522) });
  ok("E: both unobserved → HTTPS reason takes precedence",
    m.incomplete === true && m.incomplete_reason === "https_origin_not_observed",
    JSON.stringify(m.incomplete_reason));
}
{
  const m = await sslWith({ https: () => originPlain(200), http: () => originRedirect(301, "https://example.com/") });
  ok("E: fully observed scan is NOT incomplete (no over-degradation)",
    m.incomplete !== true, JSON.stringify(m.incomplete_reason));
}

console.log(`\nhttp-redirect-observation-honesty: ${pass}/${pass + fail} passed`);
if (fail) { console.error("http-redirect-observation-honesty validation FAILED"); process.exit(1); }
console.log("http-redirect-observation-honesty validation passed");
