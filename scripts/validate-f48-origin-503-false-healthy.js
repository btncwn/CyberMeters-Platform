#!/usr/bin/env node
//
// F-48 — CONFIRMED P1 FALSE-HEALTHY: a genuinely unavailable HTTPS origin. Node 24+.
//
// GOVERNANCE CLASSIFICATION (frozen): GOVERNANCE-RULING-F48-F51-CLASSIFICATION-001, seq 42.
// WORK ORDER: WORKORDER-F48-FALSE-HEALTHY-REMEDIATION-001, bundle 44ef6548…4a56 (seq 52).
// Canonical source pinned at 1b02610ca2247cdddcd5b4c1b3ea634673dcea69.
//
// ── THE DEFECT, measured before any change ──────────────────────────────────
// Ordinary HTTP 301 to HTTPS, then every HTTPS GET/HEAD observation returns a
// GENUINE ORIGIN 503 (server: nginx — not a Cloudflare edge error, so F-42's
// classifier correctly reads it as an origin response). The real chain produced:
//
//     headers: accessible=true status_code=503 incomplete=null missing=6
//     scan_quality = complete
//     Website: state=assessed_healthy  coverage=complete   (zero material findings)
//
// A site returning 503 to every HTTPS probe was published as HEALTHY.
//
// ── WHY, exactly ────────────────────────────────────────────────────────────
// scoring.js already refuses to judge headers off an error page: every header
// finding is gated on `status_code === 200`. That gate is correct. The defect is
// that the COMPLETENESS contract was never told the same fact — so the scan
// graded `complete`, the resolver saw no material Website finding, and "nothing
// found" became "healthy". One contract knew; the other was not informed.
//
// ── THE CORRECTION ──────────────────────────────────────────────────────────
// The headers module now declares `incomplete` with the distinct reason
// `origin_error_no_serviceable_response` when every available HTTPS observation
// is an origin 5xx. It does NOT fabricate header defects from an error page, and
// it does NOT reuse `ssl_not_available` (which would be a false claim: TLS
// worked; the application errored). Bounded to 5xx so ordinary 200/301/403/404
// behaviour is untouched.
//
// ── WHAT THIS HARNESS ASSERTS ───────────────────────────────────────────────
// Every scenario drives the REAL runHeadersModule, runTechModule, runSslModule,
// computeScore, buildScanQuality and the CANONICAL resolveCyberMotDomainStates,
// with only network observations stubbed. Verdicts are read from the resolver —
// a module-flag-only assertion would not have caught this defect in the first
// place, since every module flag looked fine.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;

const { runHeadersModule } = await import(eng("headers-scan.js"));
const { runTechModule } = await import(eng("tech-scan.js"));
const { runSslModule } = await import(eng("ssl-scan.js"));
const { computeScore } = await import(eng("scoring.js"));
const { buildScanQuality } = await import(eng("scan-engine.js"));
const { resolveCyberMotDomainStates } = await import(eng("cyber-mot-domains.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"} ${n}${!c && d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const DOMAIN = "acme.example.com";
const MATERIAL = new Set(["critical", "high", "medium"]);

const origin503 = () => new Response("<html>503 Service Unavailable</html>", {
  status: 503, headers: { "server": "nginx", "content-type": "text/html" },
});
const redirect301 = (url) => new Response(null, {
  status: 301,
  headers: { location: `https://${new URL(String(url)).hostname}/`, "server": "nginx" },
});
const originHealthy = () => new Response(
  "<html><head></head><body>wp-content</body></html>",
  { status: 200, headers: { "server": "nginx", "content-type": "text/html",
                            "strict-transport-security": "max-age=63072000" } });
const cloudflareHealthy = () => new Response(
  "<html><body>wp-content</body></html>",
  { status: 200, headers: { "server": "cloudflare", "cf-ray": "8f00-LHR", "content-type": "text/html",
                            "strict-transport-security": "max-age=63072000" } });
const signedEdge530 = () => new Response("edge", {
  status: 530, headers: { "server": "cloudflare", "cf-ray": "8f00-LHR", "content-type": "text/html" },
});
const origin404 = () => new Response("<html>not found</html>", {
  status: 404, headers: { "server": "nginx", "content-type": "text/html" },
});

const realFetch = globalThis.fetch;
async function observe(router) {
  globalThis.fetch = router;
  try {
    const headers = await runHeadersModule(DOMAIN);
    const technology_detection = await runTechModule(DOMAIN);
    const ssl = await runSslModule(DOMAIN);
    const modules = { dns: { resolves: true }, ssl, headers, technology_detection, email_security: {} };
    const scan_quality = buildScanQuality(modules);
    const findings = computeScore(modules, DOMAIN)?.findings || [];
    const website = resolveCyberMotDomainStates(
      { scan_quality, modules, findings, completed_at: "2026-08-17T00:00:00Z" }, { scanId: "f48" },
    ).find((d) => d.domain_key === "website_security");
    const websiteMaterial = findings
      .filter((f) => MATERIAL.has(f.severity) && (f.module === "ssl" || f.module === "headers" || String(f.id).startsWith("ssl_") || String(f.id).startsWith("header_")))
      .map((f) => f.id);
    return { headers, technology_detection, ssl, scan_quality, findings, websiteMaterial, website };
  } finally { globalThis.fetch = realFetch; }
}

// ── ROUTERS ─────────────────────────────────────────────────────────────────
// The exact corrected reproducer from the ruling.
const R_301_THEN_503 = async (url) =>
  (new URL(String(url)).protocol === "http:" ? redirect301(url) : origin503());
// The Governance control: every probe, including the HTTP hop, is a genuine 503.
const R_ALL_503 = async () => origin503();

// ── BAR 1 — the corrected false-healthy path closes ────────────────────────
{
  const r = await observe(R_301_THEN_503);
  ok("F48_BAR1_NEVER_COMPLETE_AND_HEALTHY",
     !(r.website?.coverage === "complete" && r.website?.state === "assessed_healthy"),
     `state=${r.website?.state} coverage=${r.website?.coverage}`);
  ok("F48_BAR1_NOT_ASSESSED_HEALTHY", r.website?.state !== "assessed_healthy", `state=${r.website?.state}`);
  ok("F48_BAR1_COVERAGE_NOT_COMPLETE", r.website?.coverage !== "complete", `coverage=${r.website?.coverage}`);
  ok("F48_BAR1_SCAN_NOT_COMPLETE", r.scan_quality.status !== "complete", `quality=${r.scan_quality.status}`);
  ok("F48_BAR1_SUMMARY_CLAIMS_NO_CLEAN_RESULT",
     !/no material issue observed/i.test(String(r.website?.summary || "")), String(r.website?.summary || ""));
  // Positive side: the honest state, so a fix that made everything "unknown" is
  // not mistaken for a fix.
  eq("F48_BAR1_STATE_IS_EVIDENCE_INSUFFICIENT", r.website?.state, "evidence_insufficient");
  eq("F48_BAR1_SCAN_QUALITY_IS_PARTIAL", r.scan_quality.status, "partial");
  // The reason must name the origin error, distinctly from F-42's edge case.
  ok("F48_BAR1_HEADERS_INCOMPLETE", r.headers.incomplete === true);
  eq("F48_BAR1_REASON_NAMES_ORIGIN_ERROR", r.headers.incomplete_reason, "origin_error_no_serviceable_response");
  ok("F48_BAR1_REASON_IS_NOT_THE_F42_REASON", r.headers.incomplete_reason !== "origin_not_observed");
  eq("F48_BAR1_OBSERVED_ORIGIN_STATUS_RECORDED", r.headers.header_observation?.origin_status, 503);
  // It must NOT fabricate header defects from an error page.
  ok("F48_BAR1_NO_FABRICATED_HEADER_FINDINGS",
     !r.websiteMaterial.some((id) => String(id).startsWith("header_")), JSON.stringify(r.websiteMaterial));
  // It must NOT claim HTTPS is unavailable — TLS worked, the application errored.
  ok("F48_BAR1_DOES_NOT_CLAIM_SSL_NOT_AVAILABLE",
     !r.websiteMaterial.includes("ssl_not_available"), JSON.stringify(r.websiteMaterial));
}

// ── BAR 2 — the Governance control must not regress ────────────────────────
{
  const r = await observe(R_ALL_503);
  eq("F48_BAR2_ALL_503_STILL_ISSUE_DETECTED", r.website?.state, "issue_detected");
  ok("F48_BAR2_REDIRECT_FINDING_STILL_MATERIAL",
     r.websiteMaterial.includes("ssl_no_http_redirect"), JSON.stringify(r.websiteMaterial));
  ok("F48_BAR2_NOT_RECLASSIFIED_HEALTHY", r.website?.state !== "assessed_healthy");
  ok("F48_BAR2_NOT_DOWNGRADED_TO_EVIDENCE_INSUFFICIENT", r.website?.state !== "evidence_insufficient");
}

// ── BAR 3 — healthy-origin controls unchanged ──────────────────────────────
{
  // A genuinely healthy site redirects HTTP to HTTPS. An earlier draft of this
  // fixture served 200 on the HTTP hop too, which legitimately raises
  // ssl_no_http_redirect and yields issue_detected. Measured against the
  // pristine baseline WITHOUT the F-48 edit: identical result, so that was a
  // fixture defect, not a regression. Corrected here rather than relaxing the
  // assertion.
  const healthyRouter = async (url) =>
    (new URL(String(url)).protocol === "http:" ? redirect301(url) : originHealthy());
  const r = await observe(healthyRouter);
  eq("F48_BAR3_HEALTHY_STATE_UNCHANGED", r.website?.state, "assessed_healthy");
  eq("F48_BAR3_HEALTHY_COVERAGE_UNCHANGED", r.website?.coverage, "complete");
  eq("F48_BAR3_HEALTHY_SCAN_QUALITY_UNCHANGED", r.scan_quality.status, "complete");
  ok("F48_BAR3_HEALTHY_HEADERS_ASSESSED", r.headers.headers_assessed === true && r.headers.incomplete !== true);

  // F-42 controls must remain intact: a real Cloudflare-fronted healthy origin.
  const cf = await observe(async (url) =>
    (new URL(String(url)).protocol === "http:" ? redirect301(url) : cloudflareHealthy()));
  eq("F48_BAR3_CF_HEALTHY_STATE_UNCHANGED", cf.website?.state, "assessed_healthy");
  ok("F48_BAR3_CF_STACK_STILL_DETECTED",
     (cf.technology_detection.technologies || []).includes("Cloudflare"), JSON.stringify(cf.technology_detection.technologies));

  // F-42's signed edge error keeps ITS OWN reason — F-48 must not relabel it.
  const edge = await observe(async () => signedEdge530());
  eq("F48_BAR3_F42_EDGE_REASON_PRESERVED", edge.headers.incomplete_reason, "origin_not_observed");
  ok("F48_BAR3_F42_EDGE_STILL_NOT_HEALTHY", edge.website?.state !== "assessed_healthy");

  // A 404 is a real application answer and is deliberately NOT swept up by the
  // 5xx rule. Without this control, a broader `!== 200` rule would silently
  // change healthy-origin behaviour.
  const notFound = await observe(async () => origin404());
  ok("F48_BAR3_CONTROL_404_NOT_TREATED_AS_ORIGIN_ERROR",
     notFound.headers.incomplete !== true,
     `incomplete=${notFound.headers.incomplete} reason=${notFound.headers.incomplete_reason}`);
}

console.log(`\nF-48 origin-503 false-healthy: ${pass}/${pass + fail} assertions passed`);
if (fail > 0) { console.error("F-48 validation FAILED"); process.exit(1); }
console.log("F-48 validation passed");
