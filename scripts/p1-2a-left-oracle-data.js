#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const repo = path.resolve(process.argv[2]);
const outputPath = path.resolve(process.argv[3]);
const at = (relative) => pathToFileURL(path.join(repo, relative)).href;
const S = await import(at("workers/scan-api/src/lib/serviceability.js"));
const T = await import(at("workers/scan-api/src/engines/tls-evidence.js"));
const { resolveCustomerAlertPresentation } = await import(at("workers/scan-api/src/engines/customer-alert-presentation.js"));
const { computeScore } = await import(at("workers/scan-api/src/engines/scoring.js"));
const { computeSecurityPosture } = await import(at("workers/scan-api/src/engines/posture-scoring.js"));

// Data-verbatim sealed oracle source; governed by EXECUTIVE-RULING-P1-2A-CHAIN-VETO-001 (canonical seq 319, bundle 5fefa1c5…).
const results = [];
const inputTupleSignatures = new Set();
let index = 0;
function check(group, name, condition, detail = null) {
  index += 1;
  const pass = Boolean(condition);
  if (detail !== null) inputTupleSignatures.add(JSON.stringify(detail));
  results.push({ index, group, name, pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}\t${index}\t${group}\t${name}`);
}
const eq = (group, name, got, expected, detail = null) =>
  check(group, name, Object.is(got, expected), detail ?? { got, expected });

const malformedStatuses = [
  ["fractional_200_5", 200.5], ["fractional_404_5", 404.5],
  ["below_range_99", 99], ["above_range_600", 600],
  ["zero", 0], ["negative", -1], ["nan", Number.NaN],
  ["infinity", Number.POSITIVE_INFINITY], ["numeric_string", "200"], ["null", null],
];
for (const [name, origin_status] of malformedStatuses) {
  const classified = S.classifyServiceability({ state: "origin_response", origin_status });
  check("STATUS_TYPE_VALUE", name,
    classified.serviceable === null
      && classified.conclusion_class === "evidence_insufficient"
      && classified.reason === "unknown_observation_shape"
      && !S.mayGroundAbsence(classified),
    classified);
}

const base = {
  observation_state: "origin_response",
  observation_completeness: "observed",
  http_redirect_validated: true,
  origin_status: null,
};
const hop = (state, origin_status, extra = {}) => ({ hop: 1, state, origin_status, ...extra });
const chain = (terminal, extra = {}) => ({ ...base, hop_observations: [terminal], ...extra });

for (const [name, value] of [
  ["string", "not-an-array"], ["record", { 0: hop("origin_response", 200) }],
  ["number", 42], ["null", null], ["boolean", false],
]) {
  eq("CONTAINER", `${name}_container_rejected`,
    S.mayGroundRedirectAbsence({ ...base, hop_observations: value }), false);
}
eq("CONTAINER", "empty_array_rejected", S.mayGroundRedirectAbsence({ ...base, hop_observations: [] }), false);
for (const [name, terminal] of [
  ["null_element", null], ["string_element", "hop"], ["array_element", ["hop"]],
  ["missing_state", { hop: 1, origin_status: 200 }],
  ["object_state", { hop: 1, state: { value: "origin_response" }, origin_status: 200 }],
]) {
  eq("CONTAINER", `${name}_rejected`, S.mayGroundRedirectAbsence({ ...base, hop_observations: [terminal] }), false);
}

eq("TERMINAL_AUTHORITY", "terminal_origin_200_positive",
  S.mayGroundRedirectAbsence(chain(hop("origin_response", 200))), true);
eq("TERMINAL_AUTHORITY", "terminal_origin_404_positive",
  S.mayGroundRedirectAbsence(chain(hop("origin_response", 404))), true);
for (const [name, state, status] of [
  ["origin_503", "origin_response", 503],
  ["origin_403", "origin_response", 403],
  ["origin_100", "origin_response", 100],
  ["origin_fractional", "origin_response", 200.5],
  ["edge_explicit_200", "cloudflare_edge_error", 200],
  ["transport_explicit_200", "transport_unavailable", 200],
  ["not_assessed_explicit_200", "not_assessed", 200],
  ["unknown_state_explicit_200", "invented_state", 200],
]) {
  eq("TERMINAL_AUTHORITY", `${name}_rejected`,
    S.mayGroundRedirectAbsence(chain(hop(state, status))), false);
}
eq("TERMINAL_AUTHORITY", "earlier_origin_terminal_edge_200_rejected",
  S.mayGroundRedirectAbsence({ ...base, hop_observations: [
    hop("origin_response", 200), { hop: 2, state: "cloudflare_edge_error", origin_status: 200 },
  ] }), false);
eq("TERMINAL_AUTHORITY", "earlier_origin_terminal_transport_200_rejected",
  S.mayGroundRedirectAbsence({ ...base, hop_observations: [
    hop("origin_response", 200), { hop: 2, state: "transport_unavailable", origin_status: 200 },
  ] }), false);
eq("TERMINAL_AUTHORITY", "terminal_edge_null_rejected",
  S.mayGroundRedirectAbsence(chain(hop("cloudflare_edge_error", null))), false);
eq("TERMINAL_AUTHORITY", "conflicting_chain_edge_terminal_origin_rejected",
  S.mayGroundRedirectAbsence(chain(hop("origin_response", 200), { observation_state: "cloudflare_edge_error" })), false);
eq("TERMINAL_AUTHORITY", "validated_false_rejected",
  S.mayGroundRedirectAbsence(chain(hop("origin_response", 200), { http_redirect_validated: false })), false);
eq("TERMINAL_AUTHORITY", "validated_missing_rejected",
  S.mayGroundRedirectAbsence({ ...base, http_redirect_validated: undefined,
    hop_observations: [hop("origin_response", 200)] }), false);
eq("TERMINAL_AUTHORITY", "completeness_incomplete_rejected",
  S.mayGroundRedirectAbsence(chain(hop("origin_response", 200), { observation_completeness: "incomplete" })), false);
eq("TERMINAL_AUTHORITY", "completeness_missing_rejected",
  S.mayGroundRedirectAbsence({ ...base, observation_completeness: undefined,
    hop_observations: [hop("origin_response", 200)] }), false);

eq("LEGACY", "typed_no_hop_field_positive", S.mayGroundRedirectAbsence(base), true);
eq("LEGACY", "typed_no_hop_with_explicit_status_rejected",
  S.mayGroundRedirectAbsence({ ...base, origin_status: 200 }), false);
eq("LEGACY", "legacy_boolean_only_rejected",
  S.mayGroundRedirectAbsence({ http_redirect_validated: true }), false);
eq("LEGACY", "no_hop_unvalidated_rejected",
  S.mayGroundRedirectAbsence({ ...base, http_redirect_validated: false }), false);

const ssl = (http_redirect_chain) => ({
  https_available: true,
  https_probe_executed: true,
  http_redirects_to_https: false,
  http_redirect_chain,
});
const badTerminal = ssl(chain(hop("cloudflare_edge_error", 200)));
const malformedContainer = ssl({ ...base, hop_observations: "bad" });
const goodTerminal = ssl(chain(hop("origin_response", 200)));
const stored503 = ssl(chain(hop("origin_response", 503)));
const alertFor = (module_evidence) => resolveCustomerAlertPresentation({
  domain_key: "website_security",
  recurrence: "insecure_redirect",
  finding_type: "ssl_no_http_redirect",
  module_evidence,
  canonical: { title: "Redirect", what_changed: "changed", recommended_action: "fix", remediation_id: "web.https.redirect" },
});
const modulesFor = (sslModule, domain = "example.com") => ({
  dns: { resolves: true }, ssl: sslModule,
  headers: { accessible: true, final_https: true, validation_uncertain: false,
    status_code: 200, values: {}, missing: ["strict-transport-security"] },
  email_security: {}, brand_monitoring: null,
});
const redirectFinding = (sslModule) => computeScore(modulesFor(sslModule), "example.com").findings
  .find((finding) => finding.id === "ssl_no_http_redirect") ?? null;
const scorecard = { last_scanned_domain: "example.com", new_assets_30d: 0,
  vendor_risk: { high: 0, medium: 0, low: 0 }, third_party_assets: 0,
  saas_exposures: 0, admin_surfaces: 0, brand_risks: { high: 0, medium: 0, low: 0 },
  certificate_risks: { risk_level: null, days_until_expiry: null } };
const posture = (sslModule) => computeSecurityPosture(scorecard, { modules: { ssl: sslModule,
  headers: { final_https: true }, email_security: null,
  admin_surface_detection: { evidence_status: "assessed_healthy", total: 0, high: 0, critical: 0 } } });

for (const [name, specimen] of [["terminal_non_origin_200", badTerminal], ["malformed_container", malformedContainer], ["stored_503", stored503]]) {
  eq("CONSUMERS", `${name}_tls_false`, T.isHttpRedirectPositivelyAbsent(specimen), false);
  eq("CONSUMERS", `${name}_alert_unavailable`, alertFor(specimen).presentation_state, "observation_unavailable");
  eq("CONSUMERS", `${name}_no_redirect_finding`, redirectFinding(specimen), null);
  eq("CONSUMERS", `${name}_posture_ssl_100`, posture(specimen).ssl_certificates.score, 100);
}
eq("CONSUMERS", "positive_tls_true", T.isHttpRedirectPositivelyAbsent(goodTerminal), true);
eq("CONSUMERS", "positive_alert", alertFor(goodTerminal).presentation_state, "positively_observed_redirect_defect");
eq("CONSUMERS", "positive_finding", redirectFinding(goodTerminal)?.severity ?? null, "medium");
eq("CONSUMERS", "positive_posture_85", posture(goodTerminal).ssl_certificates.score, 85);

const files = {
  tls: fs.readFileSync(path.join(repo, "workers/scan-api/src/engines/tls-evidence.js"), "utf8"),
  alert: fs.readFileSync(path.join(repo, "workers/scan-api/src/engines/customer-alert-presentation.js"), "utf8"),
  scoring: fs.readFileSync(path.join(repo, "workers/scan-api/src/engines/scoring.js"), "utf8"),
  insights: fs.readFileSync(path.join(repo, "workers/scan-api/src/routes/workspace-insights.js"), "utf8"),
  serviceability: fs.readFileSync(path.join(repo, "workers/scan-api/src/lib/serviceability.js"), "utf8"),
};
check("WIRING", "tls_calls_authority", /mayGroundRedirectAbsence\(chain\)/.test(files.tls));
check("WIRING", "alert_calls_tls_adapter", /isHttpRedirectPositivelyAbsent\(module_evidence\)/.test(files.alert));
check("WIRING", "scoring_calls_adapter_twice", (files.scoring.match(/isHttpRedirectPositivelyAbsent\(modules\.ssl\)/g) || []).length >= 2);
check("WIRING", "insights_calls_adapter", /const redirectValidated\s*=\s*isHttpRedirectPositivelyAbsent\(mods\.ssl\)/.test(files.insights));
check("WIRING", "terminal_state_is_input_to_classifier",
  /state:\s*last\??\.state/.test(files.serviceability), { expected: "classifier state comes from terminal hop" });
check("WIRING", "chain_state_not_borrowed_for_terminal_classifier",
  !/state:\s*chain\.observation_state,\s*\n\s*origin_status:\s*last/.test(files.serviceability),
  { expected: "no chain-state/terminal-status hybrid observation" });

const groups = {};
for (const group of [...new Set(results.map((row) => row.group))]) {
  const rows = results.filter((row) => row.group === group);
  groups[group] = { total: rows.length, pass: rows.filter((row) => row.pass).length,
    fail: rows.filter((row) => !row.pass).length,
    failed_indices: rows.filter((row) => !row.pass).map((row) => row.index) };
}
const summary = { total: results.length, pass: results.filter((row) => row.pass).length,
  fail: results.filter((row) => !row.pass).length, groups, results };
const distinctTupleCount = inputTupleSignatures.size;
if (distinctTupleCount < 20) throw new Error(`ORACLE_DISTINCT_TUPLE_COLLAPSE:${distinctTupleCount}`);
summary.distinctTupleCount = distinctTupleCount;
fs.writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`);
for (const [group, counts] of Object.entries(groups)) {
  console.log(`COUNT\t${group}\t${counts.pass}/${counts.total}\tfail=${counts.fail}\tindices=${counts.failed_indices.join(",") || "none"}`);
}
console.log(`COUNT\tTOTAL\t${summary.pass}/${summary.total}\tfail=${summary.fail}`);
process.exitCode = summary.fail === 0 ? 0 : 1;
