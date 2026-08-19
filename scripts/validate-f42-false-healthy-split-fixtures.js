#!/usr/bin/env node
//
// F-42 — CONFIRMED P1 FALSE-HEALTHY. Deterministic split-fixture proof. Node 24+.
//
// GOVERNANCE CLASSIFICATION (frozen): GOVERNANCE-RULING-GX530-I-F42-001,
// bundle 5dbbfd740f8d224f1b15abe90111c854d348502a7355a466f1de2716b8e0fa2f.
// Investigation subject: GX530-I-20260816T1930Z.md, SHA-256
// 76055f9f7352f000d3def7ee9f70f229f55638a3acaabe37056ff997a44927de.
// Measured canonical commit: 1b02610ca2247cdddcd5b4c1b3ea634673dcea69.
//
// ── THE DEFECT, as Governance proved it ─────────────────────────────────────
// `headers-scan.js` did not pass a signed Cloudflare 530 through the shared
// observation classifier, so the edge's own error page was processed as
//
//     accessible = true · headers_assessed = true · checked path = ok
//
// and the headers nobody could observe were recorded as `missing`. No
// `incomplete` was produced, so scan completeness was never disturbed. Combined
// with an SSL observation that DID reach a genuine origin — by a different
// method (HEAD) or a different endpoint (www) — the scan graded `complete` and
// the canonical Website resolver published **ASSESSED_HEALTHY** with
// finding_count 0.
//
// That is the one transition this platform forbids outright:
//
//     unobserved / insufficient evidence  →  complete  →  ASSESSED_HEALTHY
//
// ── WHAT THIS HARNESS PROVES, AND HOW ───────────────────────────────────────
// Every scenario drives the REAL producers (runHeadersModule, runTechModule,
// runSslModule), the REAL grader (buildScanQuality) and the CANONICAL customer
// resolver (resolveCyberMotDomainStates). Only `globalThis.fetch` is stubbed;
// no network call is made and no module output is hand-written.
//
// Bar item 6 is deliberate and load-bearing: the verdicts below are asserted on
// the GRADER and RESOLVER outputs, never inferred from module-local fields. A
// harness that only checked `headers.incomplete` would keep passing even if the
// customer-visible surface still said "healthy" — which is the entire defect.
//
// SCOPE: this file asserts evidence-completeness truth only. It takes no
// position on scoring/regrade semantics, changes no product behaviour, and does
// not touch cyber-mot-domains.js.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;

const { runHeadersModule } = await import(eng("headers-scan.js"));
const { runTechModule } = await import(eng("tech-scan.js"));
const { runSslModule } = await import(eng("ssl-scan.js"));
const { buildScanQuality } = await import(eng("scan-engine.js"));
const { resolveCyberMotDomainStates } = await import(eng("cyber-mot-domains.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"} ${n}${!c && d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const DOMAIN = "acme.example.com";

// ── Responses ───────────────────────────────────────────────────────────────
// SIGNED edge error: the status range AND `server: cloudflare` together. Both
// are required by the shared predicate; the unsigned control below proves it.
const signedEdge = (status = 530) => new Response("edge error page", {
  status, headers: { "server": "cloudflare", "cf-ray": "8f0000000000-LHR", "content-type": "text/html" },
});
// A genuine origin, serving a real stack marker so technology evidence is
// distinguishable from an edge page.
const originOk = () => new Response("<html><body>wp-content</body></html>", {
  status: 200,
  headers: { "server": "nginx", "content-type": "text/html", "strict-transport-security": "max-age=63072000" },
});
const originUnsigned530 = () => new Response("<html>origin said 530</html>", {
  status: 530, headers: { "server": "nginx", "content-type": "text/html" },
});
const origin503 = () => new Response("<html>service unavailable</html>", {
  status: 503, headers: { "server": "nginx", "content-type": "text/html" },
});
const cloudflareFrontedOk = () => new Response("<html><body>wp-content</body></html>", {
  status: 200,
  headers: { "server": "cloudflare", "cf-ray": "8f0000000000-LHR", "content-type": "text/html",
             "strict-transport-security": "max-age=63072000" },
});

// ── The two GX530-I split routers, reproduced exactly ───────────────────────
// A — METHOD split: the headers/tech GET hits the edge error; the SSL HEAD
//     reaches a genuine origin.
const SPLIT_A = async (_url, init = {}) =>
  ((init.method || "GET").toUpperCase() === "GET" ? signedEdge() : originOk());

// B — ENDPOINT-FALLBACK split: the headers/tech GET hits the edge error, the
//     bare HTTPS HEAD also hits it, and only the www HTTPS HEAD reaches a
//     genuine origin.
//
// FIDELITY NOTE — this router is scheme-aware on purpose. GX530-I's split B
// column records `bare=cloudflare_edge_error, www=origin_response,
// aggregate=origin_response, incomplete=null, www_fallback_used=true` together
// with "HTTP→HTTPS observed". ssl-scan probes `http://<domain>` with
// `redirect: "manual"` for exactly that hop, so the HTTP hop must be served as a
// genuine origin redirect. An earlier draft of this fixture returned the edge
// error on every method, which made ssl-scan report
// `incomplete_reason: "http_redirect_not_observed"` — a STRICTER scenario than
// the one Governance ruled on, and therefore the wrong thing to prove. The bar
// requires the exact GX530-I scenarios, so the fixture matches their measured
// column rather than a harsher variant that would flatter the fix.
const SPLIT_B = async (url, init = {}) => {
  const u = new URL(String(url));
  const method = (init.method || "GET").toUpperCase();
  if (method === "GET") return signedEdge();                       // headers/tech probes
  if (u.protocol === "http:") {                                    // ssl HTTP→HTTPS hop
    return new Response(null, { status: 301, headers: { location: `https://${u.hostname}/`, "server": "nginx" } });
  }
  return u.hostname.startsWith("www.") ? originOk() : signedEdge(); // bare vs www HTTPS HEAD
};

// Uniform: every probe, every method, every endpoint sees the signed edge error.
const UNIFORM_530 = async () => signedEdge();

const realFetch = globalThis.fetch;
async function observe(router) {
  globalThis.fetch = router;
  try {
    const headers = await runHeadersModule(DOMAIN);
    const technology_detection = await runTechModule(DOMAIN);
    const ssl = await runSslModule(DOMAIN);
    const modules = { dns: { resolves: true }, ssl, headers, technology_detection, email_security: {} };
    const scan_quality = buildScanQuality(modules);
    const report = { scan_quality, modules, findings: [], completed_at: "2026-08-16T00:00:00Z" };
    const website = resolveCyberMotDomainStates(report, { scanId: "f42" })
      .find((d) => d.domain_key === "website_security");
    return { headers, technology_detection, ssl, scan_quality, website };
  } finally { globalThis.fetch = realFetch; }
}

// The forbidden transition, asserted as one indivisible predicate on the
// GRADER + RESOLVER outputs. Named so a failure reads as the defect it is.
function assertNoFalseHealthy(label, r) {
  ok(`${label}__SCAN_QUALITY_IS_NOT_COMPLETE`, r.scan_quality.status !== "complete",
     `scan_quality=${r.scan_quality.status}`);
  ok(`${label}__WEBSITE_IS_NOT_ASSESSED_HEALTHY`, r.website?.state !== "assessed_healthy",
     `website.state=${r.website?.state}`);
  ok(`${label}__WEBSITE_COVERAGE_IS_NOT_COMPLETE`, r.website?.coverage !== "complete",
     `coverage=${r.website?.coverage}`);
  ok(`${label}__SUMMARY_CLAIMS_NO_CLEAN_RESULT`,
     !/no material issue observed/i.test(String(r.website?.summary || "")),
     String(r.website?.summary || ""));
  // Positive side, so the assertion discriminates in both directions: a fix that
  // turned everything into "unknown" would be no fix at all.
  eq(`${label}__SCAN_QUALITY_IS_PARTIAL`, r.scan_quality.status, "partial");
  eq(`${label}__WEBSITE_IS_EVIDENCE_INSUFFICIENT`, r.website?.state, "evidence_insufficient");
}

// ── BAR 1 — a signed edge error is not observed-origin evidence ─────────────
{
  const r = await observe(SPLIT_A);
  ok("F42_BAR1_HEADERS_NOT_ACCESSIBLE", r.headers.accessible === false);
  ok("F42_BAR1_HEADERS_NOT_ASSESSED", r.headers.headers_assessed === false);
  ok("F42_BAR1_HEADERS_INCOMPLETE", r.headers.incomplete === true);
  eq("F42_BAR1_HEADERS_REASON", r.headers.incomplete_reason, "origin_not_observed");
  eq("F42_BAR1_OBSERVATION_STATE", r.headers.header_observation?.state, "cloudflare_edge_error");
  // The absent headers must not read as ASSESSED absence. `missing` stays
  // populated by design (documented diagnostic), so the load-bearing guarantee
  // is that the module declares itself unassessed and incomplete beside it.
  ok("F42_BAR1_ABSENCE_IS_NOT_ASSESSED_ABSENCE",
     r.headers.headers_assessed === false && r.headers.incomplete === true);
  ok("F42_BAR1_NO_HEADER_VALUE_CAME_FROM_THE_EDGE",
     Object.values(r.headers.values || {}).every((v) => !v));
  // ...and the edge page is not customer technology evidence.
  eq("F42_BAR1_NO_TECHNOLOGY_FROM_EDGE_PAGE", r.technology_detection.technologies, []);
  ok("F42_BAR1_TECH_INCOMPLETE", r.technology_detection.incomplete === true);
  ok("F42_BAR1_EDGE_PAGE_IS_NOT_CLOUDFLARE_STACK_EVIDENCE",
     !(r.technology_detection.technologies || []).includes("Cloudflare"));
}

// ── BAR 2 — split fixture A (method split) ─────────────────────────────────
assertNoFalseHealthy("F42_BAR2_SPLIT_A", await observe(SPLIT_A));

// ── BAR 3 — split fixture B (endpoint fallback) ────────────────────────────
{
  const r = await observe(SPLIT_B);
  assertNoFalseHealthy("F42_BAR3_SPLIT_B", r);
  // The distinguishing feature of B: the www endpoint DID reach a real origin,
  // so SSL alone would look satisfied. The verdict must not follow that.
  ok("F42_BAR3_SPLIT_B_SSL_SAW_A_REAL_ORIGIN_YET_VERDICT_HOLDS",
     r.ssl.https_available === true);
}

// ── BAR 4 — uniform signed 530 stays fail-closed (regression guard) ────────
assertNoFalseHealthy("F42_BAR4_UNIFORM_530", await observe(UNIFORM_530));

// ── BAR 5 — controls: none of these may flip ───────────────────────────────
{
  // ── AMENDED under GOVERNANCE-RULING-F42-F48-CONTROL-ASSERTION-DISPOSITION-001
  //    (seq 55, bundle b1a8b580…4f03a), Option (A) BOUNDED UPDATE ─────────────
  //
  // These two controls exist to prove the F-42 edge guard does not OVER-BLOCK a
  // genuine origin response. That purpose is preserved exactly. What changed is
  // that their old predicate — `accessible === true && incomplete !== true` —
  // silently merged two different propositions:
  //
  //   1. the origin produced this response (not the Cloudflare edge);   TRUE
  //   2. therefore it is serviceable evidence for a complete header
  //      assessment;                                                    FALSE
  //
  // Seq 42 classified proposition 2 as the P1 false-healthy path: a genuine 5xx
  // treated as complete evidence yields complete -> assessed_healthy with no
  // material Website finding. So the identifiers stay (origin-response and
  // observed remain true at the raw observation layer) and the predicates now
  // assert origin IDENTITY and evidence INSUFFICIENCY separately.
  const unsigned = await observe(async () => originUnsigned530());
  ok("F42_BAR5_UNSIGNED_530_IS_AN_ORIGIN_RESPONSE",
     // origin identity: NOT classified as a Cloudflare-synthesized edge error
     unsigned.headers.header_observation?.state !== "cloudflare_edge_error"
     && unsigned.headers.incomplete_reason !== "origin_not_observed"
     // the origin answered, and that fact is retained
     && unsigned.headers.status_code === 530
     // ...but it is NOT serviceable header evidence and cannot carry healthy
     && unsigned.headers.headers_assessed === false
     && unsigned.headers.incomplete === true
     && unsigned.headers.incomplete_reason === "origin_error_no_serviceable_response",
     `state=${unsigned.headers.header_observation?.state} status=${unsigned.headers.status_code} assessed=${unsigned.headers.headers_assessed} reason=${unsigned.headers.incomplete_reason}`);

  const five03 = await observe(async () => origin503());
  ok("F42_BAR5_GENUINE_503_IS_OBSERVED",
     five03.headers.header_observation?.state !== "cloudflare_edge_error"
     && five03.headers.incomplete_reason !== "origin_not_observed"
     && five03.headers.status_code === 503
     && five03.headers.headers_assessed === false
     && five03.headers.incomplete === true
     && five03.headers.incomplete_reason === "origin_error_no_serviceable_response",
     `state=${five03.headers.header_observation?.state} status=${five03.headers.status_code} assessed=${five03.headers.headers_assessed} reason=${five03.headers.incomplete_reason}`);

  // The amendment must not let an origin 5xx reach a healthy customer verdict.
  ok("F42_BAR5_ORIGIN_5XX_CANNOT_SUPPORT_ASSESSED_HEALTHY",
     five03.website?.state !== "assessed_healthy" && unsigned.website?.state !== "assessed_healthy",
     `503=${five03.website?.state} 530unsigned=${unsigned.website?.state}`);
  // ...and must not fabricate header defects from the error page.
  ok("F42_BAR5_ORIGIN_5XX_FABRICATES_NO_HEADER_FINDING",
     Object.values(five03.headers.values || {}).every((v) => !v));

  const healthy = await observe(async () => originOk());
  eq("F42_BAR5_HEALTHY_ORIGIN_STILL_COMPLETE", healthy.scan_quality.status, "complete");
  eq("F42_BAR5_HEALTHY_ORIGIN_STILL_ASSESSED_HEALTHY", healthy.website?.state, "assessed_healthy");

  const cf = await observe(async () => cloudflareFrontedOk());
  ok("F42_BAR5_REAL_CLOUDFLARE_ORIGIN_STILL_DETECTED",
     (cf.technology_detection.technologies || []).includes("Cloudflare"),
     JSON.stringify(cf.technology_detection.technologies));
  ok("F42_BAR5_REAL_STACK_BEHIND_CLOUDFLARE_STILL_DETECTED",
     (cf.technology_detection.technologies || []).includes("WordPress"));
  eq("F42_BAR5_CLOUDFLARE_FRONTED_HEALTHY_UNCHANGED", cf.website?.state, "assessed_healthy");
}

// ── BAR 6 — the verdict is read from the grader and the resolver ───────────
// Asserted structurally so a future refactor cannot quietly reduce this file to
// module-local checks while still reporting green.
{
  const r = await observe(SPLIT_A);
  ok("F42_BAR6_GRADER_OUTPUT_IS_PRESENT",
     typeof r.scan_quality?.status === "string" && Array.isArray(r.scan_quality?.modules_skipped));
  ok("F42_BAR6_RESOLVER_OUTPUT_IS_PRESENT",
     typeof r.website?.state === "string" && r.website?.domain_key === "website_security");
  ok("F42_BAR6_GRADER_NAMES_THE_UNOBSERVED_MODULES",
     r.scan_quality.modules_skipped.includes("headers") &&
     r.scan_quality.modules_skipped.includes("technology_detection"),
     JSON.stringify(r.scan_quality.modules_skipped));
}

console.log(`\nF-42 split-fixture proof: ${pass}/${pass + fail} assertions passed`);
if (fail > 0) { console.error("F-42 split-fixture validation FAILED"); process.exit(1); }
console.log("F-42 split-fixture validation passed");
