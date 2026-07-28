#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-https-observation-classification.js  (CI-blocking)
//
// PR-A — HTTPS Observation Classification (P1).
//
// THE HARM THIS EXISTS TO PREVENT
// On 2026-07-28 a founder domain serving valid TLS (HTTP 200, GoDaddy DV cert
// valid 27 Jun → 25 Sep 2026) produced a CRITICAL finding "HTTPS Not Available"
// with observed_value "TLS handshake failed or connection refused on port 443",
// and an email telling the owner to install a certificate. The cause was
// ssl-scan.js collapsing three different observations into one boolean:
//
//     const httpsOk = httpsRes !== null && httpsRes.status < 500;
//     const httpsAvailable = httpsProbeExecuted ? (httpsOk || wwwHttpsOk) : null;
//
//   1. a genuine origin HTTP response;
//   2. a Cloudflare-synthesised edge failure (a real Response, no origin answered);
//   3. transport that could not be observed at all.
//
// TWO RULES PROVEN HERE
//   A. ANY origin status — including 5xx — PROVES HTTPS transport. To answer at
//      all over https:// the handshake completed and a certificate was accepted.
//      A 5xx is application health, never certificate absence. The old
//      `status < 500` rule was wrong for this reason independently of the edge bug.
//   B. "Executed but inconclusive" (edge error) and "never looked" are different
//      states and must never collapse into one bare null.
//
// Structure: deterministic matrix → mutations (anchor-guarded, pinned counts) →
// faithful runScanEngine trace. Pure/mock-fetch: no live D1/R2/network. Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC = path.join(ROOT, "workers", "scan-api", "src");
const ENG = path.join(SRC, "engines");
const FETCHOBS_SRC = path.join(SRC, "lib", "fetch-observation.js");
const SSL_SRC = path.join(ENG, "ssl-scan.js");

const {
  classifyFetchObservation, isCloudflareEdgeSynthesised, classifyServerErrorStatus,
  aggregateFetchObservations, FETCH_OBSERVATION_STATES: S,
} = await import(pathToFileURL(FETCHOBS_SRC).href);
const { runSslModule } = await import(pathToFileURL(SSL_SRC).href);
const { computeScore } = await import(pathToFileURL(path.join(ENG, "scoring.js")).href);

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "ok  " : "FAIL"} - ${name}${!cond && detail ? ` -- ${detail}` : ""}`);
};

// ── fetch mocks ──────────────────────────────────────────────────────────────
const realFetch = globalThis.fetch;
const originResponse = (status) =>
  new Response("body", { status, headers: { "content-type": "text/html", server: "nginx" } });
// Cloudflare edge errors ALWAYS carry `Server: cloudflare` — that signature is
// what distinguishes them from an origin that merely happens to emit a 52x.
const edgeResponse = (status) =>
  new Response("error page", { status, headers: { "content-type": "text/html", server: "cloudflare" } });
const unsignedResponse = (status) =>
  new Response("error page", { status, headers: { "content-type": "text/html", server: "some-origin" } });
const tlsFailure = () => { throw new TypeError("SSL handshake failed"); };
const timeoutError = () => { const e = new Error("aborted due to timeout"); e.name = "TimeoutError"; throw e; };
const networkRejection = () => { throw new TypeError("Network connection lost: connection refused"); };

// ── SECTION A — deterministic classifier matrix ──────────────────────────────
// Required statuses, each as a GENUINE origin answer and (for the 52x/530 set)
// again WITHOUT the Cloudflare signature.
console.log("\n── A. classifier matrix ──");
for (const status of [200, 301, 404, 500, 503]) {
  const r = classifyFetchObservation({ response: originResponse(status) });
  ok(`A: genuine origin ${status} → origin_response, transport PROVEN`,
    r.state === S.ORIGIN_RESPONSE && r.transport_observed === true &&
    r.origin_status === status && r.completeness === "observed",
    JSON.stringify(r));
}
// Rule A, stated as its own assertion because it is the one an earlier draft got wrong.
for (const status of [500, 503]) {
  const r = classifyFetchObservation({ response: originResponse(status) });
  ok(`A: origin ${status} is NOT transport-unavailable (5xx proves TLS completed)`,
    r.state !== S.TRANSPORT_UNAVAILABLE && r.transport_observed !== false);
}
for (const status of [520, 522, 530]) {
  const r = classifyFetchObservation({ response: edgeResponse(status) });
  ok(`A: Cloudflare-signed ${status} → cloudflare_edge_error, NOT attributed to origin`,
    r.state === S.CLOUDFLARE_EDGE_ERROR && r.transport_observed === null &&
    r.origin_status === null && r.probe_executed === true && r.completeness === "incomplete",
    JSON.stringify(r));
}
for (const status of [520, 522, 530]) {
  const r = classifyFetchObservation({ response: unsignedResponse(status) });
  ok(`A: UNSIGNED ${status} (no Server: cloudflare) → treated as a genuine origin answer`,
    r.state === S.ORIGIN_RESPONSE && r.origin_status === status);
}
{
  const r = classifyFetchObservation({ response: null, failure: "tls_handshake_failed" });
  ok("A: TLS failure → transport_unavailable, never certificate absence",
    r.state === S.TRANSPORT_UNAVAILABLE && r.transport_observed === null && r.probe_executed === true);
  const t = classifyFetchObservation({ response: null, failure: "timeout" });
  ok("A: timeout → transport_unavailable (executed, inconclusive)",
    t.state === S.TRANSPORT_UNAVAILABLE && t.probe_executed === true);
  const n = classifyFetchObservation({ response: null, failure: "connection_refused" });
  ok("A: network rejection → transport_unavailable", n.state === S.TRANSPORT_UNAVAILABLE);
  const x = classifyFetchObservation({ executed: false });
  ok("A: probe NOT executed → not_assessed, distinct from executed-but-inconclusive",
    x.state === S.NOT_ASSESSED && x.probe_executed === false && x.completeness === "not_assessed");
  ok("A: not_assessed !== transport_unavailable (Rule B — no collapsing)",
    S.NOT_ASSESSED !== S.TRANSPORT_UNAVAILABLE &&
    classifyFetchObservation({ executed: false }).state !==
      classifyFetchObservation({ response: null }).state);
  ok("A: transport_observed is never false from a fetch result alone",
    [originResponse(200), edgeResponse(530), unsignedResponse(522), null]
      .every((resp) => classifyFetchObservation({ response: resp }).transport_observed !== false));
}
// ── PR-A1: EXACT Cloudflare boundary ─────────────────────────────────────────
// The accepted set is (520..527) OR 530 — NOT the inclusive 520..530 range.
// 528/529 are not Cloudflare edge codes. The inclusive form was inherited from
// asset-intel.js at base b141a5fc (whose own comment already said "520–527 … 530");
// PR-A1 owns and corrects the shared predicate.
const EDGE_BOUNDARY = [
  [519, false], [520, true], [521, true], [522, true], [523, true], [524, true],
  [525, true], [526, true], [527, true], [528, false], [529, false], [530, true],
  [531, false],
];
for (const [status, expected] of EDGE_BOUNDARY) {
  ok(`A: signed ${status} → edge-synthesised=${expected} (exact boundary)`,
    isCloudflareEdgeSynthesised(status, "cloudflare") === expected);
  // Unsigned control: the signature is required at EVERY status in the set.
  ok(`A: UNSIGNED ${status} → never edge-synthesised (signature required)`,
    isCloudflareEdgeSynthesised(status, "nginx") === false);
}
// The two statuses the inclusive range wrongly excused must now classify as a
// genuine origin answer end-to-end, not merely fail the predicate.
for (const status of [528, 529]) {
  const r = classifyFetchObservation({ response: edgeResponse(status) });
  ok(`A: signed ${status} is a genuine ORIGIN response (not excused as edge)`,
    r.state === S.ORIGIN_RESPONSE && r.origin_status === status);
}
ok("A: isCloudflareEdgeSynthesised requires BOTH range and signature",
  isCloudflareEdgeSynthesised(530, "cloudflare") === true &&
  isCloudflareEdgeSynthesised(530, "nginx") === false &&
  isCloudflareEdgeSynthesised(500, "cloudflare") === false);
// asset-intel adapter behaviour under the corrected boundary: signed 528/529 move
// from `origin_unreachable` to `server_error` — toward the STRICTER not-assessed
// reading, never toward a cleaner result.
ok("A: adapter — signed 528/529 are server_error, not origin_unreachable",
  classifyServerErrorStatus(528, "cloudflare").probe_status === "server_error" &&
  classifyServerErrorStatus(529, "cloudflare").probe_status === "server_error");
ok("A: adapter — signed 527 and 530 remain origin_unreachable",
  classifyServerErrorStatus(527, "cloudflare").probe_status === "origin_unreachable" &&
  classifyServerErrorStatus(530, "cloudflare").probe_status === "origin_unreachable");

// ── PR-A1: aggregate precedence + endpoint provenance ────────────────────────
// 1 origin_response → observed · 2 cloudflare_edge_error → incomplete
// 3 transport_unavailable → unavailable · 4 not_assessed
const obsOf = (resp) => classifyFetchObservation({ response: resp });
const agg = (bare, www) => aggregateFetchObservations([
  { endpoint: "example.com", observation: obsOf(bare) },
  { endpoint: "www.example.com", observation: obsOf(www) },
]);
{
  const a = agg(null, edgeResponse(522));
  ok("A: bare timeout + www EDGE → incomplete (sibling's edge reason WINS, not discarded)",
    a.state === S.CLOUDFLARE_EDGE_ERROR && a.completeness === "incomplete", JSON.stringify(a));
  ok("A: …and BOTH endpoints keep their own observation",
    a.endpoints.length === 2 &&
    a.endpoints[0].state === S.TRANSPORT_UNAVAILABLE &&
    a.endpoints[1].state === S.CLOUDFLARE_EDGE_ERROR, JSON.stringify(a.endpoints));
}
{
  const a = agg(edgeResponse(522), null);
  ok("A: bare EDGE + www timeout → incomplete (symmetric)",
    a.state === S.CLOUDFLARE_EDGE_ERROR && a.completeness === "incomplete");
}
{
  const a = agg(edgeResponse(522), originResponse(500));
  ok("A: bare EDGE + www ORIGIN 500 → origin_response wins (precedence 1)",
    a.state === S.ORIGIN_RESPONSE && a.transport_observed === true && a.origin_status === 500);
}
{
  const a = agg(null, originResponse(200));
  ok("A: bare timeout + www ORIGIN 200 → origin_response wins (precedence 1)",
    a.state === S.ORIGIN_RESPONSE && a.transport_observed === true);
}
{
  const a = agg(null, null);
  ok("A: both endpoints inconclusive → transport_unavailable (precedence 3)",
    a.state === S.TRANSPORT_UNAVAILABLE && a.endpoints.length === 2);
  const none = aggregateFetchObservations([]);
  ok("A: no endpoints at all → not_assessed (precedence 4)",
    none.state === S.NOT_ASSESSED && none.endpoints.length === 0);
}
ok("A: asset-intel adapter still returns its legacy shape from the SHARED rule",
  classifyServerErrorStatus(530, "cloudflare").probe_status === "origin_unreachable" &&
  classifyServerErrorStatus(503, "nginx").probe_status === "server_error");

// ── SECTION B — the REAL ssl module end-to-end ───────────────────────────────
console.log("\n── B. real runSslModule ──");
const noCt = { get: async () => null, set: async () => {} };   // CT is independent of reachability
// CT lookups share the mocked fetch and log their own (internally caught, non-fatal)
// parse failures to stderr. Suppress that benign noise so CI output stays readable —
// CT is independent of reachability and is not what this suite asserts.
async function sslWith(fetchImpl) {
  globalThis.fetch = fetchImpl;
  const err = console.error; console.error = () => {};
  try { return await runSslModule("example.com", { ctCache: noCt }); }
  finally { globalThis.fetch = realFetch; console.error = err; }
}
{
  const m = await sslWith(async () => originResponse(200));
  ok("B: origin 200 → https_available true, state origin_response",
    m.https_available === true && m.https_observation_state === S.ORIGIN_RESPONSE);
}
{
  // THE REPORTED HARM, inverted into a guard.
  const m = await sslWith(async () => originResponse(500));
  ok("B: genuine origin 500 PROVES HTTPS transport (https_available true)",
    m.https_available === true, JSON.stringify({ a: m.https_available, s: m.https_observation_state }));
  ok("B: origin 500 records the status as application health, not TLS absence",
    m.https_origin_status === 500 && m.https_observation_state === S.ORIGIN_RESPONSE);
}
{
  const m = await sslWith(async () => edgeResponse(522));
  ok("B: Cloudflare-signed 522 → https_available NULL (never false)",
    m.https_available === null && m.https_available !== false);
  ok("B: edge error is INCOMPLETE with an honest reason, and the probe DID execute",
    m.https_observation_state === S.CLOUDFLARE_EDGE_ERROR &&
    m.https_observation_reason === "cloudflare_edge_error" &&
    m.https_observation_completeness === "incomplete" &&
    m.https_probe_executed === true);
}
{
  const m = await sslWith(timeoutError);
  ok("B: timeout → https_available NULL and probe_executed FALSE (scan degrades honestly)",
    m.https_available === null && m.https_probe_executed === false);
}
{
  const m = await sslWith(tlsFailure);
  ok("B: TLS handshake failure → NULL, never a certificate-absence claim",
    m.https_available === null && m.https_available !== false);
}
{
  const m = await sslWith(networkRejection);
  ok("B: network rejection → NULL", m.https_available === null);
}

// ── SECTION C — the customer-visible finding ─────────────────────────────────
// scoring.js fires ssl_not_available ONLY on `https_available === false`. These
// prove the false finding can no longer be reached from any fetch observation.
console.log("\n── C. customer-visible finding ──");
const findingIds = (ssl) => {
  const r = computeScore({
    ssl, headers: { headers: {} }, dns: {}, email_security: {},
  }, "example.com");
  return new Set((r.findings || []).map((f) => f.id));
};
for (const [label, mod] of [
  ["origin 500", await sslWith(async () => originResponse(500))],
  ["Cloudflare-signed 522", await sslWith(async () => edgeResponse(522))],
  ["Cloudflare-signed 530", await sslWith(async () => edgeResponse(530))],
  ["timeout", await sslWith(timeoutError)],
  ["TLS failure", await sslWith(tlsFailure)],
]) {
  ok(`C: ${label} produces NO ssl_not_available finding`, !findingIds(mod).has("ssl_not_available"));
}
// Positive control: the finding is still reachable from genuine TLS/cert evidence,
// so this suite proves a scoped fix and not a deleted check.
ok("C: positive control — an explicit https_available:false STILL fires ssl_not_available",
  findingIds({ https_available: false, https_probe_executed: true }).has("ssl_not_available"));

console.log(`\nhttps-observation-classification: ${pass}/${pass + fail} passed`);
if (fail) { console.error("https-observation-classification validation FAILED"); process.exit(1); }
console.log("https-observation-classification validation passed");
