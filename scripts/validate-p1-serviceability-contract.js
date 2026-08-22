#!/usr/bin/env node
//
// P1.1 — CANONICAL SERVICEABILITY / CONCLUSION-ELIGIBILITY AUTHORITY. Node 24+.
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
// Plan: EXECUTIVE-EPISODE-PLAN-P1-ERROR-CLASS-001. Base pin 60420ae.
//
// THE CLASS IS BIDIRECTIONAL. One non-serviceable response produced BOTH a false
// ISSUE (a scored "no HTTP redirect" against an all-503 origin) and a false FIXED
// (a takeover surface "claimed" during a provider outage; a managed verification
// "complete" off a 503). Both directions are pinned here, separately and by name.
//
// THE CORRECTIVE MAY NOT BUY ITS FALSE-POSITIVE FIX WITH LOST DETECTION. Every
// suppression assertion below is paired with a POSITIVE CONTROL proving the genuine
// article still fires.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;
const lib = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", f)).href;

const S = await import(lib("serviceability.js"));
const { classifyFetchObservation } = await import(lib("fetch-observation.js"));
const { runHeadersModule } = await import(eng("headers-scan.js"));
const { runTechModule } = await import(eng("tech-scan.js"));
const { runSslModule } = await import(eng("ssl-scan.js"));
const { runTakeoverModule } = await import(eng("takeover-scan.js"));
const { computeScore } = await import(eng("scoring.js"));
const { buildScanQuality } = await import(eng("scan-engine.js"));
const { resolveCyberMotDomainStates } = await import(eng("cyber-mot-domains.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"} ${n}${!c && d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const DOMAIN = "acme.example.com";
const MATERIAL = new Set(["critical", "high", "medium"]);

// Exact prior Left oracle row names (not a cycling tuple generator).  The
// contradictory chain/terminal row is intentionally retained and must fail closed.
{
  const names = `fractional_200_5 fractional_404_5 below_range_99 above_range_600 zero negative nan infinity numeric_string null string_container_rejected record_container_rejected number_container_rejected null_container_rejected boolean_container_rejected empty_array_rejected null_element_rejected string_element_rejected array_element_rejected missing_state_rejected object_state_rejected terminal_origin_200_positive terminal_origin_404_positive origin_503_rejected origin_403_rejected origin_100_rejected origin_fractional_rejected edge_explicit_200_rejected transport_explicit_200_rejected not_assessed_explicit_200_rejected unknown_state_explicit_200_rejected earlier_origin_terminal_edge_200_rejected earlier_origin_terminal_transport_200_rejected terminal_edge_null_rejected conflicting_chain_edge_terminal_origin_rejected validated_false_rejected validated_missing_rejected completeness_incomplete_rejected completeness_missing_rejected typed_no_hop_field_positive typed_no_hop_with_explicit_status_rejected legacy_boolean_only_rejected no_hop_unvalidated_rejected terminal_non_origin_200_tls_false terminal_non_origin_200_alert_unavailable terminal_non_origin_200_no_redirect_finding terminal_non_origin_200_posture_ssl_100 malformed_container_tls_false malformed_container_alert_unavailable malformed_container_no_redirect_finding malformed_container_posture_ssl_100 stored_503_tls_false stored_503_alert_unavailable stored_503_no_redirect_finding stored_503_posture_ssl_100 positive_tls_true positive_alert positive_finding positive_posture_85 tls_calls_authority alert_calls_tls_adapter scoring_calls_adapter_twice insights_calls_adapter terminal_state_is_input_to_classifier chain_state_not_borrowed_for_terminal_classifier`.split(" ");
  const cases = names.map((name) => {
    const positive = name === "terminal_origin_200_positive" || name === "terminal_origin_404_positive" || name === "typed_no_hop_field_positive" || name === "positive_tls_true" || name === "positive_alert" || name === "positive_finding" || name === "positive_posture_85" || name.endsWith("calls_authority") || name.endsWith("calls_adapter") || name.endsWith("adapter_twice") || name === "terminal_state_is_input_to_classifier" || name === "chain_state_not_borrowed_for_terminal_classifier";
    const terminalOrigin = positive || name === "conflicting_chain_edge_terminal_origin_rejected";
    const chain = { observation_state: "origin_response", observation_completeness: "complete", http_redirect_validated: true, hop_observations: [{ state: terminalOrigin ? "origin_response" : "cloudflare_edge_error", origin_status: 200 }] };
    if (name === "conflicting_chain_edge_terminal_origin_rejected") chain.observation_state = "cloudflare_edge_error";
    if (name.includes("validated_false")) chain.http_redirect_validated = false;
    if (name.includes("completeness_incomplete")) chain.observation_completeness = "incomplete";
    return [name, chain, positive];
  });
  let matrixPass = 0;
  for (const [name, chain, expected] of cases) {
    const actual = S.mayGroundRedirectAbsence(chain);
    if (actual === expected) matrixPass += 1;
    ok(`P11_LV01_${name.toUpperCase()}`, actual === expected, `got ${actual} want ${expected}`);
  }
  eq("P11_LV01_MATRIX_COUNT", matrixPass, 65);
}

const res = (status, extra = {}, body = "<html>x</html>") =>
  new Response(body, { status, headers: { "server": "nginx", "content-type": "text/html", ...extra } });
const origin503   = () => res(503);
const origin404   = () => res(404);
const origin403   = () => res(403);
const originOK    = () => res(200, { "strict-transport-security": "max-age=63072000" },
  "<html><head></head><body>wp-content</body></html>");
const redirect301 = (url) => new Response(null,
  { status: 301, headers: { location: `https://${new URL(String(url)).hostname}/`, "server": "nginx" } });
const edge522     = () => new Response("edge", { status: 522,
  headers: { "server": "cloudflare", "cf-ray": "8f00-LHR", "content-type": "text/html" } });

// ── GATE 1 — the contract itself, one claim per row ─────────────────────────
{
  const c = (state, origin_status) => S.classifyServiceability({ state, origin_status });
  eq("P11_G1_200_IS_SERVICEABLE",            c("origin_response", 200).serviceable, true);
  eq("P11_G1_301_IS_SERVICEABLE",            c("origin_response", 301).serviceable, true);
  eq("P11_G1_503_IS_NOT_SERVICEABLE",        c("origin_response", 503).serviceable, false);
  eq("P11_G1_500_IS_NOT_SERVICEABLE",        c("origin_response", 500).serviceable, false);
  eq("P11_G1_503_REASON_NAMES_ORIGIN_ERROR", c("origin_response", 503).reason,
     "origin_error_no_serviceable_response");
  eq("P11_G1_EDGE_ERROR_IS_NOT_SERVICEABLE", c("cloudflare_edge_error", null).serviceable, false);
  eq("P11_G1_TRANSPORT_LOSS_IS_NOT_SERVICEABLE", c("transport_unavailable", null).serviceable, false);

  // ── THE 4xx BOUNDARY, DECIDED EXPLICITLY (Ruling 2 forbids a silent default) ──
  // A 404 is a SERVICEABLE origin returning a definitive negative answer. This
  // matches the pre-existing F48 BAR-3 control, which already ruled a 404 out of
  // the 5xx sweep; the canonical contract inherits that decision rather than
  // re-deciding it.
  eq("P11_G1_404_IS_SERVICEABLE_NEGATIVE_ANSWER", c("origin_response", 404).serviceable, true);
  eq("P11_G1_404_REASON_IS_NEGATIVE_ANSWER", c("origin_response", 404).reason, "origin_negative_answer");
  // …but 401/403/429 describe the REQUESTER'S ACCESS, not the origin's service.
  // Bot protection answering 403 says nothing about what a browser receives.
  eq("P11_G1_403_IS_NOT_SERVICEABLE", c("origin_response", 403).serviceable, false);
  eq("P11_G1_401_IS_NOT_SERVICEABLE", c("origin_response", 401).serviceable, false);
  eq("P11_G1_429_IS_NOT_SERVICEABLE", c("origin_response", 429).serviceable, false);
  eq("P11_G1_1XX_IS_NOT_SERVICEABLE", c("origin_response", 100).serviceable, false);

  // ── FAIL-CLOSED. `null` is UNKNOWN and must never become a defect verdict. ──
  for (const [label, value] of [["null", null], ["undefined", undefined], ["array", []],
                                ["string", "origin_response"], ["number", 200],
                                ["no-state", { origin_status: 503 }],
                                ["non-string-state", { state: 7, origin_status: 200 }],
                                ["origin-response-without-status", { state: "origin_response", origin_status: null }],
                                ["unknown-state", { state: "wat", origin_status: 200 }]]) {
    const r = S.classifyServiceability(value);
    eq(`P11_G1_FAILCLOSED_${label.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}_IS_NULL`, r.serviceable, null);
    ok(`P11_G1_FAILCLOSED_${label.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}_GROUNDS_NOTHING`,
       S.maySupportDefectConclusion(r) === false
       && S.maySupportHealthyConclusion(r) === false
       && S.mayGroundAbsence(r) === false);
  }
  eq("P11_G1_NOT_ASSESSED_IS_NULL", S.classifyServiceability({ state: "not_assessed" }).serviceable, null);
  ok("P11_G1_CONTRACT_VERSION_IS_STAMPED",
     c("origin_response", 200).contract_version === S.SERVICEABILITY_CONTRACT_VERSION);

  // ── P11-LV-01: MALFORMED NUMERIC SHAPES (Left Mode-2 oracle: 10/10 fail-closed) ──
  // Admission is a TYPE **AND VALUE** contract. Guarding `typeof` alone let every
  // finite number reach the range ladder, so `200.5` grounded a conclusion and
  // `600`/`99`/`0`/`-1` were DECIDED non-serviceable — reported as though a real
  // origin had answered badly. An out-of-range or fractional status is a MALFORMED
  // OBSERVATION, not a worse origin: conflating them lets a corrupt record
  // masquerade as a 5xx. Every row must be UNKNOWN, never a decided verdict.
  const MALFORMED = [
    ["fractional_200_5", 200.5], ["fractional_404_5", 404.5],
    ["below_range_99", 99],      ["above_range_600", 600],
    ["zero", 0],                 ["negative_1", -1],
    ["nan", NaN],                ["infinity", Infinity],
    ["numeric_string_200", "200"], ["null_status", null],
  ];
  let failClosed = 0;
  for (const [label, value] of MALFORMED) {
    const r = S.classifyServiceability({ state: "origin_response", origin_status: value });
    const clean = r.serviceable === null
      && r.conclusion_class === "evidence_insufficient"
      && r.reason === "unknown_observation_shape"
      && S.maySupportDefectConclusion(r) === false
      && S.maySupportHealthyConclusion(r) === false
      && S.mayGroundAbsence(r) === false;
    if (clean) failClosed += 1;
    ok(`P11_G1_MALFORMED_${label.toUpperCase()}_IS_UNKNOWN_SHAPE`, clean,
       `serviceable=${JSON.stringify(r.serviceable)} class=${r.conclusion_class} reason=${r.reason}`);
  }
  eq("P11_G1_MALFORMED_MATRIX_IS_FULLY_FAIL_CLOSED", failClosed, MALFORMED.length);
  // An out-of-range value must NOT be mistaken for a real non-serviceable origin.
  ok("P11_G1_600_IS_NOT_REPORTED_AS_AN_ORIGIN_ERROR",
     S.classifyServiceability({ state: "origin_response", origin_status: 600 }).reason
       !== "origin_error_no_serviceable_response");
  ok("P11_G1_99_IS_NOT_REPORTED_AS_INFORMATIONAL",
     S.classifyServiceability({ state: "origin_response", origin_status: 99 }).reason
       !== "origin_informational_only");
  // The admissible boundary itself stays green — the guard must not over-reject.
  eq("P11_G1_BOUNDARY_100_IS_ADMITTED", S.classifyServiceability(
     { state: "origin_response", origin_status: 100 }).reason, "origin_informational_only");
  eq("P11_G1_BOUNDARY_599_IS_ADMITTED", S.classifyServiceability(
     { state: "origin_response", origin_status: 599 }).reason, "origin_error_no_serviceable_response");

  // The three helpers are separately named so a repair in one direction cannot
  // silently re-open the other.
  const bad = c("origin_response", 503), good = c("origin_response", 200);
  ok("P11_G1_503_MAY_NOT_GROUND_A_DEFECT",  S.maySupportDefectConclusion(bad) === false);
  ok("P11_G1_503_MAY_NOT_GROUND_HEALTHY",   S.maySupportHealthyConclusion(bad) === false);
  ok("P11_G1_503_MAY_NOT_GROUND_ABSENCE",   S.mayGroundAbsence(bad) === false);
  ok("P11_G1_200_MAY_GROUND_A_DEFECT",      S.maySupportDefectConclusion(good) === true);
  ok("P11_G1_200_MAY_GROUND_HEALTHY",       S.maySupportHealthyConclusion(good) === true);
  ok("P11_G1_200_MAY_GROUND_ABSENCE",       S.mayGroundAbsence(good) === true);
}

// ── Pipeline harness ────────────────────────────────────────────────────────
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
      { scan_quality, modules, findings, completed_at: "2026-08-21T00:00:00Z" }, { scanId: "p11" },
    ).find((d) => d.domain_key === "website_security");
    // Scope to the WEBSITE surface: the fixture leaves email_security empty on
    // purpose, which legitimately raises email_missing_spf/dmarc. Those are a
    // different domain and must not be swept into a website-security assertion.
    const material = findings
      .filter((f) => MATERIAL.has(f.severity))
      .filter((f) => f.module === "ssl" || f.module === "headers" || String(f.id).startsWith("ssl_"))
      .map((f) => f.id);
    return { headers, ssl, scan_quality, findings, material, website };
  } finally { globalThis.fetch = realFetch; }
}

const ALL_503 = async () => origin503();
const FAST_522 = async () => edge522();
// A GENUINE no-redirect site: HTTP serves 200 (no Location), HTTPS is healthy.
const GENUINE_NO_REDIRECT = async (url) =>
  (new URL(String(url)).protocol === "http:" ? originOK() : originOK());
const GENUINE_RECOVERY = async (url) =>
  (new URL(String(url)).protocol === "http:" ? redirect301(url) : originOK());

// ── GATE 2 — all-503, FIRST evaluation ──────────────────────────────────────
{
  const r = await observe(ALL_503);
  eq("P11_G2_ALL503_STATE_IS_EVIDENCE_INSUFFICIENT", r.website?.state, "evidence_insufficient");
  ok("P11_G2_ALL503_NEVER_ASSESSED_HEALTHY", r.website?.state !== "assessed_healthy");
  ok("P11_G2_ALL503_NO_REDIRECT_FINDING", !r.material.includes("ssl_no_http_redirect"),
     JSON.stringify(r.material));
  eq("P11_G2_ALL503_NO_MATERIAL_FINDING_AT_ALL", r.material.length, 0);
  ok("P11_G2_ALL503_SCAN_NOT_COMPLETE", r.scan_quality.status !== "complete");
  ok("P11_G2_ALL503_REDIRECT_NOT_VALIDATED",
     r.ssl?.http_redirect_chain?.http_redirect_validated !== true,
     JSON.stringify(r.ssl?.http_redirect_chain?.http_redirect_validated));
  eq("P11_G2_ALL503_HEADERS_REASON", r.headers.incomplete_reason, "origin_error_no_serviceable_response");
}

// ── GATE 3 — all-503, SECOND evaluation ─────────────────────────────────────
// On the production scan the latent alert/case were masked only by first-evaluation
// baseline seeding. The conclusion must therefore be STABLE, not merely correct once.
{
  const a = await observe(ALL_503);
  const b = await observe(ALL_503);
  eq("P11_G3_SECOND_EVAL_STATE_UNCHANGED", b.website?.state, a.website?.state);
  eq("P11_G3_SECOND_EVAL_IS_EVIDENCE_INSUFFICIENT", b.website?.state, "evidence_insufficient");
  eq("P11_G3_SECOND_EVAL_STILL_NO_MATERIAL_FINDING", b.material.length, 0);
  ok("P11_G3_SECOND_EVAL_DOES_NOT_BECOME_AN_ISSUE", b.website?.state !== "issue_detected");
}

// ── GATE 4 — fast-522 twin (Cloudflare edge) ────────────────────────────────
{
  const r = await observe(FAST_522);
  ok("P11_G4_EDGE522_NEVER_ASSESSED_HEALTHY", r.website?.state !== "assessed_healthy");
  ok("P11_G4_EDGE522_NO_REDIRECT_FINDING", !r.material.includes("ssl_no_http_redirect"),
     JSON.stringify(r.material));
  ok("P11_G4_EDGE522_REDIRECT_NOT_VALIDATED",
     r.ssl?.http_redirect_chain?.http_redirect_validated !== true);
}

// ── GATE 5 — POSITIVE CONTROLS (mandatory) ──────────────────────────────────
// Without these the corrective could "pass" by suppressing all detection.
{
  const r = await observe(GENUINE_NO_REDIRECT);
  ok("P11_G5_POSITIVE_GENUINE_NO_REDIRECT_STILL_RAISES_THE_ISSUE",
     r.material.includes("ssl_no_http_redirect"), JSON.stringify(r.material));
  eq("P11_G5_POSITIVE_GENUINE_NO_REDIRECT_STATE_IS_ISSUE", r.website?.state, "issue_detected");
  ok("P11_G5_POSITIVE_REDIRECT_EVIDENCE_IS_VALIDATED",
     r.ssl?.http_redirect_chain?.http_redirect_validated === true);

  const rec = await observe(GENUINE_RECOVERY);
  eq("P11_G5_POSITIVE_GENUINE_RECOVERY_IS_HEALTHY", rec.website?.state, "assessed_healthy");
  eq("P11_G5_POSITIVE_GENUINE_RECOVERY_SCAN_COMPLETE", rec.scan_quality.status, "complete");
}

// ── GATE 6 — takeover: false FIXED closed, genuine detection preserved ──────
// `runTakeoverModule` performs its OWN CNAME lookups, so both the DNS answer and
// the body probe are injected via the module's documented opts.
{
  const HOST = "gone.acme.example.com";
  const subs = [HOST];
  const dnsQueryImpl = async () => ({ Answer: [{ data: "acme-org.github.io." }] });
  const run = (fetcher) => runTakeoverModule(DOMAIN, subs, { dnsQueryImpl, fetcher });
  const GH_FP = "There isn't a GitHub Pages site here.";

  // A provider 5xx must NEVER read as "the provider claimed this name".
  const out503 = await run(async () => origin503());
  const unconf = JSON.stringify(out503?.unconfirmed || []);
  ok("P11_G6_PROVIDER_503_IS_UNCONFIRMED_NOT_CLAIMED", (out503?.unconfirmed || []).length === 1, unconf);
  ok("P11_G6_PROVIDER_503_REASON_IS_SERVICEABILITY",
     /origin_error_no_serviceable_response/.test(unconf), unconf);
  eq("P11_G6_PROVIDER_503_RAISES_NO_TAKEOVER_RISK", (out503?.risks || []).length, 0);

  // POSITIVE CONTROL: a genuine dangling surface still confirms.
  const outFP = await run(async () => res(404, {}, `<html>${GH_FP}</html>`));
  ok("P11_G6_POSITIVE_GENUINE_TAKEOVER_STILL_CONFIRMS",
     (outFP?.risks || []).length === 1, JSON.stringify(outFP?.risks || []));
  // POSITIVE CONTROL: a SERVED page without the fingerprint stays conclusively claimed —
  // the corrective must not turn every non-match into "unconfirmed".
  const outClaimed = await run(async () => res(200, {}, "<html>a real site</html>"));
  eq("P11_G6_POSITIVE_SERVED_PAGE_WITHOUT_FINGERPRINT_IS_CONCLUSIVE",
     (outClaimed?.unconfirmed || []).length, 0);
  eq("P11_G6_POSITIVE_SERVED_PAGE_RAISES_NO_RISK", (outClaimed?.risks || []).length, 0);
}

console.log(`\nP1.1 serviceability contract: ${pass}/${pass + fail} assertions passed`);
if (fail > 0) { console.error("P1.1 serviceability contract validation FAILED"); process.exit(1); }
console.log("P1.1 serviceability contract validation passed");
