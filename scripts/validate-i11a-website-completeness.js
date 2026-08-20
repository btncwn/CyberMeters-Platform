#!/usr/bin/env node
//
// Item 11A — Website Security header/technology completeness, 52x/530 arm.
// Mutation-tested, CI-blocking. Node 24+.
//
// THE DEFECT THIS EXISTS TO PREVENT (measured at canonical main 1b02610c):
// `headers-scan.js` treated ANY non-null Response as proof the site answered
// (`if (!getRes) continue; accessible = true;`). A Cloudflare-synthesised edge
// failure — 520-527 or 530 with `server: cloudflare` — IS a real Response with
// real headers, so:
//
//   accessible            -> true          (a Response came back)
//   incomplete            -> never set     (gated on `accessible`)
//   missing[]             -> every header  (from an origin that never served)
//   buildScanQuality      -> "complete"    (nothing to catch)
//   canVerify("headers")  -> true          (module "ran")
//
// i.e. the exact `fetch-failed ≠ missing` confusion the Item 11A completeness
// criterion exists to prevent, one class removed from the null-response defect
// that validate-probe-evidence-honesty.js already covers.
//
// `tech-scan.js` had the same class with the opposite sign: an edge error page
// carries `server: cloudflare` + `cf-ray`, which it published as a DETECTED
// TECHNOLOGY of the customer while every real stack marker was absent.
//
// THE CONTRACT: only an ORIGIN response may support a header or technology
// verdict. Everything else is `incomplete`, with a reason that says which kind
// of nothing it was. No status code acquires a new meaning here — the predicate
// is the pre-existing shared one in lib/fetch-observation.js (status range AND
// `server: cloudflare`, both required), consumed rather than re-implemented.
//
// SCOPE BOUNDARY: this harness asserts completeness/evidence honesty only. It
// takes no position on HTTP 530 semantics beyond that shared predicate, and
// asserts nothing about the F-42 / GX530-I candidate.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcPath = (...p) => path.join(root, "workers", "scan-api", "src", ...p);
const eng = (f) => pathToFileURL(srcPath("engines", f)).href;

const { runHeadersModule } = await import(eng("headers-scan.js"));
const { runTechModule } = await import(eng("tech-scan.js"));
const { buildScanQuality } = await import(eng("scan-engine.js"));
const { moduleCompletionGate } = await import(eng("asm-cases.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"} ${n}${!c && d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

// ── Fixtures are the REAL modules' output ───────────────────────────────────
// Hand-written module shapes would keep passing after someone deleted the guard
// from the engine, which is the regression this exists to catch. Every probe
// goes through safeFetch → global fetch, so the fixture is the network.
const realFetch = globalThis.fetch;
async function withFetch(impl, fn) {
  globalThis.fetch = impl;
  try { return await fn(); } finally { globalThis.fetch = realFetch; }
}

const edge = (status) => async () => new Response("error", {
  status,
  headers: { "server": "cloudflare", "cf-ray": "8f0000000000-LHR", "content-type": "text/html" },
});
// Same status, NO cloudflare signature: the shared predicate requires BOTH, so
// this must stay an origin response. Without this control the harness would pass
// on a mutant that keyed on the status range alone.
const originWithEdgeStatus = async () => new Response("<html>real origin error</html>", {
  status: 530,
  headers: { "server": "nginx", "content-type": "text/html" },
});
// A genuine origin 5xx proves transport and must NOT be swallowed as incomplete.
const originFiveHundred = async () => new Response("<html>oops</html>", {
  status: 503,
  headers: { "server": "nginx", "content-type": "text/html" },
});
const originHealthy = async () => new Response(
  "<html><head><script src='https://cdn.example.com/a.js'></script></head><body>wp-content</body></html>",
  { status: 200, headers: { "content-type": "text/html", "server": "cloudflare", "cf-ray": "8f00-LHR",
                            "strict-transport-security": "max-age=63072000" } });
const TIMEOUT = async () => { const e = new Error("aborted due to timeout"); e.name = "TimeoutError"; throw e; };

// ── HEADERS ─────────────────────────────────────────────────────────────────
for (const status of [520, 523, 527, 530]) {
  const h = await withFetch(edge(status), () => runHeadersModule("acme.example.com"));
  ok(`C1_HEADERS_EDGE_${status}_IS_INCOMPLETE`, h.incomplete === true);
  eq(`C1_HEADERS_EDGE_${status}_REASON`, h.incomplete_reason, "origin_not_observed");
  ok(`C1_HEADERS_EDGE_${status}_NOT_ACCESSIBLE`, h.accessible === false);
  ok(`C1_HEADERS_EDGE_${status}_NOT_ASSESSED`, h.headers_assessed === false);
  eq(`C1_HEADERS_EDGE_${status}_OBSERVATION_STATE`, h.header_observation?.state, "cloudflare_edge_error");
  // present/missing stay populated as diagnostics by design, but the module must
  // never present itself as having assessed them.
  ok(`C1_HEADERS_EDGE_${status}_NO_VALUES_FROM_EDGE`,
     Object.values(h.values || {}).every((v) => !v));
}

const hEdge = await withFetch(edge(530), () => runHeadersModule("acme.example.com"));
eq("C1_HEADERS_EDGE_FORCES_PARTIAL",
   buildScanQuality({ headers: hEdge }).status, "partial");
ok("C1_HEADERS_EDGE_CANNOT_VERIFY",
   moduleCompletionGate({ headers: hEdge }, buildScanQuality({ headers: hEdge })).canVerify("headers") === false);

// CONTROLS — these must NOT flip.
// ── AMENDED under GOVERNANCE-RULING-F42-F48-CONTROL-ASSERTION-DISPOSITION-001
//    (seq 55, bundle b1a8b580…4f03a), Option (A) BOUNDED UPDATE ──────────────
// Same amendment as the F-42 split-fixture controls: the identifiers keep their
// origin-vs-edge purpose, but the predicates no longer equate "the origin
// answered" with "this is serviceable, complete header evidence". Seq 42 showed
// that equation produces the P1 false-healthy path. Origin identity and evidence
// sufficiency are now asserted as the two separate facts they always were.
const hOriginEdgeStatus = await withFetch(originWithEdgeStatus, () => runHeadersModule("acme.example.com"));
ok("C1_CONTROL_530_WITHOUT_CF_SIGNATURE_IS_ORIGIN",
   // origin identity preserved: not an edge-synthesized error
   hOriginEdgeStatus.header_observation?.state !== "cloudflare_edge_error"
   && hOriginEdgeStatus.incomplete_reason !== "origin_not_observed"
   && hOriginEdgeStatus.status_code === 530            // the origin answered; retained
   && hOriginEdgeStatus.headers_assessed === false     // but not a header assessment
   && hOriginEdgeStatus.incomplete === true
   && hOriginEdgeStatus.incomplete_reason === "origin_error_no_serviceable_response",
   `state=${hOriginEdgeStatus.header_observation?.state} status=${hOriginEdgeStatus.status_code} reason=${hOriginEdgeStatus.incomplete_reason}`);
const hOrigin503 = await withFetch(originFiveHundred, () => runHeadersModule("acme.example.com"));
ok("C1_CONTROL_ORIGIN_503_IS_OBSERVED",
   hOrigin503.header_observation?.state !== "cloudflare_edge_error"
   && hOrigin503.incomplete_reason !== "origin_not_observed"
   && hOrigin503.status_code === 503
   && hOrigin503.headers_assessed === false
   && hOrigin503.incomplete === true
   && hOrigin503.incomplete_reason === "origin_error_no_serviceable_response",
   `state=${hOrigin503.header_observation?.state} status=${hOrigin503.status_code} reason=${hOrigin503.incomplete_reason}`);
// The origin-5xx reason must stay DISTINCT from the signed-edge reason, so the
// two conditions can never be conflated in either direction.
ok("C1_CONTROL_ORIGIN_5XX_REASON_DISTINCT_FROM_EDGE",
   hOrigin503.incomplete_reason !== hEdge.incomplete_reason
   && hEdge.incomplete_reason === "origin_not_observed",
   `origin5xx=${hOrigin503.incomplete_reason} edge=${hEdge.incomplete_reason}`);
const hHealthy = await withFetch(originHealthy, () => runHeadersModule("acme.example.com"));
ok("C1_CONTROL_HEALTHY_ORIGIN_UNCHANGED",
   hHealthy.accessible === true && hHealthy.incomplete !== true && hHealthy.headers_assessed === true);

// REGRESSION — the pre-existing not-executed path keeps its own distinct reason.
const hTimeout = await withFetch(TIMEOUT, () => runHeadersModule("acme.example.com"));
ok("C1_REGRESSION_TIMEOUT_STILL_INCOMPLETE", hTimeout.incomplete === true);
eq("C1_REGRESSION_TIMEOUT_REASON_UNCHANGED", hTimeout.incomplete_reason, "probe_not_executed");
// Asserted as an exact PAIR, not as inequality. Inequality passed even with the
// guard deleted (the edge reason became `undefined`, which is trivially "not
// equal"), so it could not discriminate — the mutation run caught that and the
// assertion was tightened rather than the expectation relaxed.
eq("C1_REASONS_ARE_DISTINCT",
   [hTimeout.incomplete_reason, hEdge.incomplete_reason],
   ["probe_not_executed", "origin_not_observed"]);

// ── TECHNOLOGY ──────────────────────────────────────────────────────────────
const tEdge = await withFetch(edge(530), () => runTechModule("acme.example.com"));
ok("C1_TECH_EDGE_IS_INCOMPLETE", tEdge.incomplete === true);
eq("C1_TECH_EDGE_REASON", tEdge.incomplete_reason, "origin_not_observed");
eq("C1_TECH_EDGE_NO_TECHNOLOGY_INFERRED", tEdge.technologies, []);
ok("C1_TECH_EDGE_DOES_NOT_CLAIM_CLOUDFLARE",
   !(tEdge.technologies || []).includes("Cloudflare"));
eq("C1_TECH_EDGE_FORCES_PARTIAL",
   buildScanQuality({ technology_detection: tEdge }).status, "partial");

// CONTROL — a real origin that genuinely sits behind Cloudflare must still be
// detected as such. Over-blocking would delete a true signal, which is the
// opposite failure and just as wrong.
const tHealthy = await withFetch(originHealthy, () => runTechModule("acme.example.com"));
ok("C1_CONTROL_REAL_CLOUDFLARE_ORIGIN_STILL_DETECTED",
   (tHealthy.technologies || []).includes("Cloudflare") && tHealthy.incomplete !== true);
ok("C1_CONTROL_REAL_STACK_STILL_DETECTED",
   (tHealthy.technologies || []).includes("WordPress"));

// ── SURFACE PARITY — the marker must REACH the customer, not be relabelled ──
//
// Production produced `origin_error_no_serviceable_response` correctly, yet the
// customer surface rendered "Skipped modules: headers", which asserts the module
// never ran. `incomplete` (it observed, and what it observed was unusable) and
// `skipped` (it never executed) are different propositions; conflating them hid the
// F-48 marker from acceptance. These pin the separation and the customer wording.
const { resolveCyberMotDomainStates } = await import(eng("cyber-mot-domains.js"));
const sq503 = buildScanQuality({ headers: hOrigin503 });

ok("C1_SURFACE_INCOMPLETE_LIST_EXISTS", Array.isArray(sq503.modules_incomplete));
eq("C1_SURFACE_INCOMPLETE_CARRIES_MODULE_AND_REASON",
   sq503.modules_incomplete,
   [{ module: "headers", incomplete_reason: "origin_error_no_serviceable_response" }]);
// Compatibility: the legacy list is unchanged, so existing consumers do not shift.
ok("C1_SURFACE_LEGACY_SKIPPED_LIST_UNCHANGED",
   (sq503.modules_skipped || []).includes("headers"));
// A null/absent reason would let a surface fall back to a bare module name and lose
// the marker. Requires the ENTRY to exist and the reason to be a non-empty string:
// an empty list previously satisfied a bare `!== null` via undefined, which is
// exactly the hole a mutant found.
ok("C1_SURFACE_REASON_IS_NOT_NULL",
   sq503.modules_incomplete.length === 1
   && typeof sq503.modules_incomplete[0].incomplete_reason === "string"
   && sq503.modules_incomplete[0].incomplete_reason.length > 0);

const wsCard = resolveCyberMotDomainStates({
  scan_quality: sq503,
  modules: { headers: hOrigin503 },
  findings: [],
}).find((d) => d.domain_key === "website_security");
ok("C1_SURFACE_CARD_IS_EVIDENCE_INSUFFICIENT", wsCard?.state === "evidence_insufficient");
ok("C1_SURFACE_CARD_STATES_THE_REASON",
   /origin error no serviceable response/.test(wsCard?.summary || ""),
   `summary=${wsCard?.summary}`);
ok("C1_SURFACE_CARD_DOES_NOT_CLAIM_NEVER_COLLECTED",
   !/could not be collected/.test(wsCard?.summary || ""));
ok("C1_SURFACE_CARD_IS_NEVER_HEALTHY", wsCard?.state !== "assessed_healthy");

// ── NULL-REASON (TIMEOUT) CASE — must NOT borrow the insufficient-evidence words ──
//
// A module cut off by its budget also carries incomplete === true, but with NO
// reason: it observed nothing at all. Saying "ran, but evidence was insufficient"
// there asserts an observation that never happened. Measured on the live edgefail
// scan (scan_92310f91): headers outcome deadline_exceeded, incomplete true,
// incomplete_reason null. The two cases must stay distinguishable forever.
const hTimedOut = { incomplete: true, source: "http_headers" }; // no incomplete_reason
const sqTimeout = buildScanQuality({ headers: hTimedOut });
eq("C1_SURFACE_TIMEOUT_CARRIES_NULL_REASON",
   sqTimeout.modules_incomplete, [{ module: "headers", incomplete_reason: null }]);

const wsTimeout = resolveCyberMotDomainStates({
  scan_quality: sqTimeout,
  modules: { headers: hTimedOut },
  findings: [],
}).find((d) => d.domain_key === "website_security");
ok("C1_SURFACE_TIMEOUT_SAYS_DID_NOT_COMPLETE",
   /did not complete within the scan budget/.test(wsTimeout?.summary || ""),
   `summary=${wsTimeout?.summary}`);
ok("C1_SURFACE_TIMEOUT_DOES_NOT_CLAIM_UNUSABLE_EVIDENCE",
   !/was not usable this scan/.test(wsTimeout?.summary || ""),
   `summary=${wsTimeout?.summary}`);
ok("C1_SURFACE_TIMEOUT_IS_NEVER_HEALTHY", wsTimeout?.state !== "assessed_healthy");
// And the reasoned case must NOT borrow the timeout words either — the separation
// has to hold in BOTH directions or one wording could swallow the other.
ok("C1_SURFACE_REASONED_DOES_NOT_CLAIM_TIMEOUT",
   !/did not complete within the scan budget/.test(wsCard?.summary || ""));

// CONTROL — a healthy origin must acquire NO incomplete entry, or the guard would
// pass by marking everything incomplete.
const hSurfaceHealthy = await withFetch(originHealthy, () => runHeadersModule("acme.example.com"));
eq("C1_SURFACE_CONTROL_HEALTHY_HAS_NO_INCOMPLETE",
   buildScanQuality({ headers: hSurfaceHealthy }).modules_incomplete, []);

console.log(`\nI11A website completeness: ${pass}/${pass + fail} assertions passed`);
if (fail > 0) { console.error("I11A website-completeness validation FAILED"); process.exit(1); }
console.log("I11A website-completeness validation passed");
