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
// computeScore, buildScanQuality and the CANONICAL resolveSecurityCheckDomainStates,
// with only network observations stubbed. Verdicts are read from the resolver —
// a module-flag-only assertion would not have caught this defect in the first
// place, since every module flag looked fine.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;

const { runHeadersModule, hstsPolicyOf, buildHstsHostPolicy } = await import(eng("headers-scan.js"));
const { runTechModule } = await import(eng("tech-scan.js"));
const { runSslModule } = await import(eng("ssl-scan.js"));
const { computeScore } = await import(eng("scoring.js"));
const { buildScanQuality } = await import(eng("scan-engine.js"));
const { resolveSecurityCheckDomainStates } = await import(eng("security-check-domains.js"));
const { runDomainSecurityEnrichmentModule } = await import(eng("domain-enrichment.js"));
const { buildDseFindings } = await import(eng("dse-findings.js"));

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
// A healthy origin sends the full security-header set. (23 Oct 2026: with only
// HSTS, the other five header checks read "Validation Uncertain" here because a
// constructed Response has no final URL; resting "healthy" on unvalidated
// header checks is the defect the sibling block below closes.)
const SECURITY_HEADER_SET = {
  "strict-transport-security": "max-age=63072000",
  "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  "x-frame-options": "DENY", "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin", "permissions-policy": "camera=()",
};
const originHealthy = () => new Response(
  "<html><head></head><body>wp-content</body></html>",
  { status: 200, headers: { "server": "nginx", "content-type": "text/html", ...SECURITY_HEADER_SET } });
const cloudflareHealthy = () => new Response(
  "<html><body>wp-content</body></html>",
  { status: 200, headers: { "server": "cloudflare", "cf-ray": "8f00-LHR", "content-type": "text/html", ...SECURITY_HEADER_SET } });
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
    const website = resolveSecurityCheckDomainStates(
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

// ── BAR 2 — SUCCEEDED to the three-state contract (P1.1) ───────────────────
//
// CANONICAL AUTHORITY — cited at its TRUE TYPE. Three Governance RULINGS exist in
// the ledger; the two remaining artifacts are Executive and are NOT rulings:
//   seq  42  GOVERNANCE-RULING-F48-F51-CLASSIFICATION-001        (ruling — descriptive classification)
//   seq  63  GOVERNANCE-RULING-F48-REMEDIATION-ACCEPTANCE-001    (ruling — normative, all-503 issue retention)
//   seq 262  GOVERNANCE-RULING-I11A-ACC-P2-01-BAR-CONFLICT-001   (ruling — FINAL, authorizes this succession)
// Context, NOT authority:
//   seq 260  GOVERNANCE-SUBMISSION-…-BAR-CONFLICT-001-ADDENDUM-001  (Executive submission)
//   seq 263  EXECUTIVE-MEASUREMENT-F48-BAR2-AUTHORITY-PROVENANCE-001 (Executive measurement, no repair authority)
// The operative authority for the BAR2 succession is seq 262. The prior behaviour was
// RATIFIED, then SUPERSEDED — never "unauthorized".
//
// WHAT CHANGED AND WHY. BAR 2 pinned the all-503 shape to `issue_detected` with a
// MATERIAL `ssl_no_http_redirect`. That finding was itself produced from
// non-serviceable evidence: every probe, including the HTTP hop, returned a genuine
// origin 503, so CyberMeters never observed whether the origin redirects. Asserting
// the defect was the false-ISSUE direction of the same class F-48 fixed in the
// false-HEALTHY direction. Two validators therefore contradicted each other, and
// `validate-i11a-website-completeness`'s `evidence_insufficient` direction is the
// CONTROLLING semantics (named per the ADDENDUM).
//
// THE ANTI-FALSE-HEALTHY FLOOR IS PRESERVED, not weakened — by explicit replacement
// assertions below, never by deleting the guard.
{
  const r = await observe(R_ALL_503);
  // The floor, restated explicitly. This is the F-48 guarantee and it still holds.
  ok("F48_BAR2_ALL_503_NEVER_ASSESSED_HEALTHY", r.website?.state !== "assessed_healthy",
     `state=${r.website?.state}`);
  ok("F48_BAR2_ALL_503_COVERAGE_NEVER_COMPLETE", r.website?.coverage !== "complete",
     `coverage=${r.website?.coverage}`);
  ok("F48_BAR2_ALL_503_SCAN_NEVER_COMPLETE", r.scan_quality.status !== "complete",
     `quality=${r.scan_quality.status}`);
  // The succession: the honest third state, not a defect verdict.
  eq("F48_BAR2_ALL_503_IS_EVIDENCE_INSUFFICIENT", r.website?.state, "evidence_insufficient");
  // The false ISSUE is gone. A redirect decision that was never observed may not be
  // published as an observed redirect defect.
  ok("F48_BAR2_NO_UNOBSERVED_REDIRECT_FINDING",
     !r.websiteMaterial.includes("ssl_no_http_redirect"), JSON.stringify(r.websiteMaterial));
  // …and it must not be replaced by some OTHER fabricated material finding.
  eq("F48_BAR2_NO_FABRICATED_MATERIAL_FINDING_AT_ALL", r.websiteMaterial.length, 0);
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

// ── Sibling (item 15 corpus, 23 Oct 2026): an UNCERTAIN header observation ──
// A 202 or a 403 challenge page gets every header check titled "— Validation
// Uncertain" (info). Those assert nothing, so they were not material, and
// Website Security resolved "Assessed — no material issue observed" on 8 of
// 22 healthy corpus states. It must read provisional instead; a fully-headered
// 200 must still read healthy.
{
  const bare = (status) => async (url) => (new URL(String(url)).protocol === "http:" ? redirect301(url)
    : new Response("<html><body>please wait</body></html>", { status, headers: { "server": "nginx", "content-type": "text/html" } }));
  const allHeaders = async (url) => (new URL(String(url)).protocol === "http:" ? redirect301(url)
    : new Response("<html><body>wp-content</body></html>", { status: 200, headers: {
        "server": "nginx", "content-type": "text/html",
        "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
        "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        "x-frame-options": "DENY", "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin", "permissions-policy": "camera=()" } }));
  for (const status of [202, 403]) {
    const r = await observe(bare(status));
    const uncertain = r.findings.filter((f) => /^header_missing_/.test(f.id) && f.severity === "info");
    ok(`UNCERTAIN_${status}_HEADERS_READ_VALIDATION_UNCERTAIN`, uncertain.length > 0 && uncertain.every((f) => /Validation Uncertain/.test(f.title)),
      r.findings.map((f) => `${f.id}:${f.severity}`).join(","));
    ok(`UNCERTAIN_${status}_WEBSITE_NOT_HEALTHY`, r.website?.state !== "assessed_healthy", `state=${r.website?.state}`);
    ok(`UNCERTAIN_${status}_SUMMARY_SAYS_NOT_VALIDATED`,
      !/^Assessed — no material issue observed/.test(String(r.website?.summary || "")), String(r.website?.summary || ""));
    // Codex C-36 (P2): the customer sentence itself is pinned, so it cannot be
    // emptied or reworded into a clean result while these checks still pass.
    eq(`UNCERTAIN_${status}_PROVISIONAL_SENTENCE_EXACT`, [r.website?.state, r.website?.summary], ["provisional",
      "No material issue observed, but the security headers could not be validated this scan " +
      "(the site may have answered through bot protection, or its headers varied by page)."]);
  }
  const healthy = await observe(allHeaders);
  eq("UNCERTAIN_CONTROL_FULLY_HEADERED_200_STAYS_HEALTHY", healthy.website?.state, "assessed_healthy");

  // Item 15 re-run (24 Oct 2026, corpus-mind): a 403 page that carries every
  // header EXCEPT HSTS. Since E2 the HSTS policy is not_observed on a 403, so no
  // HSTS finding fires and no other header check is uncertain - the domain read
  // assessed_healthy. The headers module itself says it could not validate.
  const allButHsts403 = async (url) => (new URL(String(url)).protocol === "http:" ? redirect301(url)
    : new Response("<html><body>blocked</body></html>", { status: 403, headers: {
        "server": "nginx", "content-type": "text/html",
        "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        "x-frame-options": "DENY", "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin", "permissions-policy": "camera=()" } }));
  const blocked = await observe(allButHsts403);
  eq("UNCERTAIN_403_ALL_BUT_HSTS_POLICY_NOT_OBSERVED", blocked.headers?.hsts_policy?.state, "not_observed");
  eq("UNCERTAIN_403_ALL_BUT_HSTS_WEBSITE_NOT_HEALTHY", [blocked.website?.state, blocked.website?.coverage], ["provisional", "partial"]);
  // Control: the same headers on a 200 WITH HSTS stays healthy.
}

// ── Item 15 fix B/B2 (23 Oct 2026): HSTS is the apex's own, host-scoped policy ─
// RFC 6797 §§8.1-8.3: a policy binds to the host that sent it; includeSubDomains
// extends it downward; a www policy never covers its apex; preload needs the
// apex's own HTTPS answer. Rows are Codex C-40's counterexamples plus the
// corpus-79/-60 summary disagreement.
{
  const withUrl = (response, url) => { Object.defineProperty(response, "url", { value: url }); return response; };
  const WWW = `www.${DOMAIN}`;
  const site = ({ apexHsts = null, wwwHsts = null, apexNoHttps = false, direct = false, wwwStatus = 200, apexStatus = 301 }) => async (input) => {
    const url = new URL(String(input));
    if (url.protocol === "http:") {
      const to = apexNoHttps ? `https://${WWW}/uk` : `https://${url.hostname}/`;
      return withUrl(new Response(null, { status: 301, headers: { location: to } }), String(input));
    }
    if (url.hostname === DOMAIN) {
      if (apexNoHttps) throw new TypeError("fetch failed");
      if (direct) {
        const { "strict-transport-security": _ignored, ...rest } = SECURITY_HEADER_SET;
        return withUrl(new Response("<html><body>shop</body></html>", { status: 200, headers: {
          "content-type": "text/html", ...rest, ...(apexHsts ? { "strict-transport-security": apexHsts } : {}) } }), String(input));
      }
      if (apexStatus !== 301) return withUrl(new Response("slow down", { status: apexStatus, headers: apexHsts ? { "strict-transport-security": apexHsts } : {} }), String(input));
      return withUrl(new Response(null, { status: 301, headers: { location: `https://${WWW}/uk`, ...(apexHsts ? { "strict-transport-security": apexHsts } : {}) } }), String(input));
    }
    const { "strict-transport-security": _omit, ...others } = SECURITY_HEADER_SET;
    return withUrl(new Response("<html><body>shop</body></html>", { status: wwwStatus, headers: {
      "content-type": "text/html", ...others, ...(wwwHsts ? { "strict-transport-security": wwwHsts } : {}) } }), String(input));
  };
  const run = async (shape) => {
    globalThis.fetch = site(shape);
    try {
      const headers = await runHeadersModule(DOMAIN);
      const enrich = runDomainSecurityEnrichmentModule(DOMAIN, { headers, dns: {} });
      const scored = computeScore({ dns: { resolves: true }, headers, ssl: { http_redirects_to_https: true }, technology_detection: {}, email_security: {} }, DOMAIN)?.findings || [];
      const all = [...scored, ...buildDseFindings(enrich, DOMAIN)];
      const hsts = all.filter((f) => /hsts|strict_transport/.test(f.id));
      return { headers, enrich, hsts, ids: hsts.map((f) => f.id).sort() };
    } finally { globalThis.fetch = realFetch; }
  };
  const STRONG = "max-age=31536000; includeSubdomains; preload";

  // Corpus-79/-60 (fix B): eligible apex, short www — no finding, summary agrees.
  const eligible = await run({ apexHsts: STRONG, wwwHsts: "max-age=900" });
  eq("HSTS_APEX_RECORDED", eligible.headers.apex_https_response?.strict_transport_security, STRONG);
  eq("HSTS_APEX_POLICY_JUDGED", [eligible.enrich.hsts.source, eligible.enrich.hsts.preload_eligible], ["apex", true]);
  eq("HSTS_APEX_ELIGIBLE_NO_FALSE_FINDINGS", eligible.ids, []);
  eq("HSTS_SUMMARY_AGREES_STRONG_APEX", eligible.headers.header_strength?.["strict-transport-security"]?.status, "valid");

  // C-40 row 1: apex answers HTTPS without HSTS; www has strong HSTS.
  const apexNone = await run({ apexHsts: null, wwwHsts: STRONG });
  eq("B2_APEX_ABSENT_NOT_PRESENT_NOT_ELIGIBLE", [apexNone.enrich.hsts.present, apexNone.enrich.hsts.preload_eligible, apexNone.headers.hsts_policy?.state], [false, false, "absent"]);
  const missing = apexNone.hsts.find((f) => f.id === "header_missing_strict_transport_security");
  ok("B2_APEX_ABSENT_SAYS_EXACTLY_WHAT_IS_TRUE",
    Boolean(missing) && missing.description.includes(`The apex (${DOMAIN}) sends no HSTS; ${WWW} does.`), missing?.description);
  ok("B2_APEX_ABSENT_SUMMARY_HAS_NO_HSTS", !apexNone.headers.header_strength?.["strict-transport-security"]
    && apexNone.headers.missing.includes("strict-transport-security"), JSON.stringify(apexNone.headers.missing));

  // C-40 row 2: apex never answers HTTPS; HTTP redirects to strongly protected www.
  const noHttps = await run({ apexNoHttps: true, wwwHsts: STRONG });
  eq("B2_APEX_NO_HTTPS_NOT_ASSESSED", [noHttps.headers.hsts_policy?.state, noHttps.enrich.hsts.present, noHttps.enrich.hsts.preload_eligible, noHttps.enrich.hsts.error],
    ["not_observed", false, false, "apex_https_not_observed"]);
  eq("B2_APEX_NO_HTTPS_NO_HSTS_CLAIM_EITHER_WAY", noHttps.ids, []);

  // C-40 row 3: apex strong WITH includeSubDomains; www omits — protected, no missing finding.
  const covered = await run({ apexHsts: STRONG, wwwHsts: null });
  eq("B2_APEX_COVERS_WWW_NO_MISSING_FINDING", covered.ids, []);
  eq("B2_APEX_COVERS_WWW_POLICY", [covered.headers.hsts_policy?.final_covered, covered.headers.missing.includes("strict-transport-security")], [true, false]);

  // C-40 row 4: apex strong WITHOUT includeSubDomains; www omits — a www observation, never an apex absence.
  const uncovered = await run({ apexHsts: "max-age=31536000", wwwHsts: null });
  ok("B2_UNCOVERED_WWW_IS_A_WWW_OBSERVATION",
    uncovered.ids.includes("header_hsts_redirect_host_uncovered") && !uncovered.ids.includes("header_missing_strict_transport_security"), JSON.stringify(uncovered.ids));
  ok("B2_UNCOVERED_WWW_NAMES_WWW",
    (uncovered.hsts.find((f) => f.id === "header_hsts_redirect_host_uncovered")?.description || "").startsWith(`${WWW} sends no HSTS`));

  // B3 (item 15 re-run, corpus-90): the www answer was a 429 with no HSTS —
  // absence on a non-serviceable response is not evidence of an uncovered host.
  const rateLimited = await run({ apexHsts: "max-age=31536000", wwwHsts: null, wwwStatus: 429 });
  ok("B3_UNCOVERED_NEEDS_SERVICEABLE_FINAL_RESPONSE", !rateLimited.ids.includes("header_hsts_redirect_host_uncovered"), JSON.stringify(rateLimited.ids));

  // E2 (item 15 re-run, corpus-90): the apex answered 429 without HSTS. That
  // absence is not evidence: not_observed, no missing-HSTS claim.
  const apexLimited = await run({ apexHsts: null, wwwHsts: "max-age=7889238", apexStatus: 429 });
  eq("E2_APEX_429_WITHOUT_HSTS_IS_NOT_ABSENT", [apexLimited.headers.hsts_policy?.state, apexLimited.ids.includes("header_missing_strict_transport_security")], ["not_observed", false]);
  // R1: a header on a non-serviceable answer (a WAF/CDN 429 page) is not the
  // origin's policy either: not_observed, no HSTS claim either way.
  const apexLimitedWithHsts = await run({ apexHsts: STRONG, wwwHsts: null, apexStatus: 429 });
  eq("E2_APEX_429_WITH_HSTS_IS_NOT_OBSERVED", [apexLimitedWithHsts.headers.hsts_policy?.state, apexLimitedWithHsts.headers.hsts_policy?.value],
    ["not_observed", null]);
  ok("E2_APEX_429_WITH_HSTS_CLAIMS_NOTHING", !apexLimitedWithHsts.ids.some((id) => /hsts|strict_transport_security/.test(id)), JSON.stringify(apexLimitedWithHsts.ids));

  // R1 follow-up (24 Oct 2026): a legacy result without hsts_policy and without a
  // recorded apex answer, or an apex answer without a status, is not_observed:
  // neither the final page's value nor its absence stands for the apex.
  const legacyMissing = hstsPolicyOf({ values: { "strict-transport-security": null }, response_url: "https://example.org/" }, "example.org");
  const legacyPresent = hstsPolicyOf({ values: { "strict-transport-security": STRONG }, response_url: "https://example.org/" }, "example.org");
  eq("LEGACY_RESULT_WITHOUT_APEX_IS_NOT_OBSERVED", [legacyMissing.state, legacyPresent.state, legacyPresent.value, legacyPresent.final_value, legacyMissing.legacy],
    ["not_observed", "not_observed", null, STRONG, true]);
  const noStatus = hstsPolicyOf({ apex_https_response: { url: "https://example.org", strict_transport_security: STRONG }, values: {} }, "example.org");
  eq("APEX_ANSWER_WITHOUT_STATUS_IS_NOT_OBSERVED", noStatus.state, "not_observed");
  eq("APEX_200_STILL_PRESENT", buildHstsHostPolicy({ domain: "example.org", apexObserved: true, apexValue: STRONG, apexStatus: 200 }).state, "present");

  // C-40 row 5 (reverse): short apex, strong www — the apex is what is judged.
  const shortApex = await run({ apexHsts: "max-age=900", wwwHsts: STRONG });
  eq("B2_SUMMARY_AGREES_SHORT_APEX", shortApex.headers.header_strength?.["strict-transport-security"]?.status, "weak");
  ok("B2_SHORT_APEX_FINDINGS_FIRE", ["dse_hsts_short_maxage", "header_weak_hsts"].every((id) => shortApex.ids.includes(id)), JSON.stringify(shortApex.ids));

  // Direct-apex controls.
  eq("B2_DIRECT_APEX_STRONG_NO_FINDING", (await run({ direct: true, apexHsts: STRONG })).ids, []);
  const directNone = await run({ direct: true, apexHsts: null });
  ok("B2_DIRECT_APEX_ABSENT_GENUINE_MISSING", directNone.ids.includes("header_missing_strict_transport_security")
    && !directNone.hsts.find((f) => f.id === "header_missing_strict_transport_security").description.includes("sends no HSTS;"), JSON.stringify(directNone.ids));
}

console.log(`\nF-48 origin-503 false-healthy: ${pass}/${pass + fail} assertions passed`);
if (fail > 0) { console.error("F-48 validation FAILED"); process.exit(1); }
console.log("F-48 validation passed");
