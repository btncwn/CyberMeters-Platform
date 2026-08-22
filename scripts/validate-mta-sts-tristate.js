#!/usr/bin/env node
// MTA-STS tri-state contract: producer coherence, canonical admission, and the
// PRODUCTION consumer paths (score, business impacts, findings, transport
// boundary). Forged evidence must fail closed at every consumer OUTPUT, and a
// zero from unavailable evidence must never be byte-identical to a zero from
// admitted absence (denominator honesty).
import {
  fetchMtaSts,
  computeEmailScore,
  buildEmailBusinessImpacts,
  buildEmailIntelFindings,
} from "../workers/scan-api/src/engines/email-intel.js";
import { mtaStsAdmission, buildEmailTransportDetails } from "../workers/scan-api/src/engines/email-analysis.js";

let passed = 0;
const failures = [];
// Collect-all: every assertion runs so a mutant is killed by its NAMED failing
// assertion in the output, and a red run shows the complete failure surface.
const ok = (name, value) => {
  if (!value) {
    failures.push(name);
    console.log(`FAIL ${name}`);
    return;
  }
  passed += 1;
  console.log(`PASS ${name}`);
};
const originalFetch = globalThis.fetch;
const run = async (responseOrError) => {
  const fetcher = async () => {
    if (responseOrError instanceof Error) throw responseOrError;
    return responseOrError;
  };
  try { return await fetchMtaSts("example.com", { fetcher }); } finally { globalThis.fetch = originalFetch; }
};
const policy = () => new Response("version: STSv1\nmode: enforce\nmax_age: 86400\n", { status: 200 });

for (const [name, response, state, reason] of [
  ["200-valid-policy", policy(), "present", "origin_response"],
  ["404-served", new Response("not found", { status: 404 }), "definitive_absent", "well_known_404"],
  ["503-origin", new Response("unavailable", { status: 503 }), "unavailable", "http_5xx"],
  ["transport", null, "unavailable", "transport_error"],
  ["timeout", Object.assign(new Error("timed out"), { name: "TimeoutError" }), "unavailable", "timeout"],
]) {
  const result = await run(response);
  ok(`${name}: observation state`, result.observation_state === state);
  ok(`${name}: reason`, result.reason === reason);
  // Serviceability SHAPE: every producer outcome carries a shaped serviceability
  // object with a boolean verdict — never null, never a bare token.
  ok(`${name}: serviceability shape`,
    result.serviceability !== null && typeof result.serviceability === "object" &&
    typeof result.serviceability.serviceable === "boolean");
  ok(`${name}: serviceability verdict coheres`,
    result.serviceability.serviceable === (state !== "unavailable"));
  // enabled coherence: a policy is "enabled" only when it was actually present.
  ok(`${name}: enabled coherence`, result.enabled === (state === "present"));
  const admission = mtaStsAdmission(result);
  ok(`${name}: score admission`, admission.score_admitted === (state === "present"));
  ok(`${name}: finding admission`, admission.missing_finding === (state === "definitive_absent"));
  ok(`${name}: remediation admission`, admission.remediation_admitted === (state === "definitive_absent"));
  const detail = buildEmailTransportDetails({ mta_sts: result });
  ok(`${name}: unavailable maps to incomplete`, state !== "unavailable" || detail.mta_sts_detail.coverage_state === "incomplete");
}

const malformed = mtaStsAdmission({ observation_state: "present", status_code: 200, reason: null, serviceability: null });
ok("malformed present shape is fail-closed", malformed.state === "unavailable" && !malformed.score_admitted && !malformed.missing_finding);

// ── PRODUCTION consumer paths: forged evidence fails closed at the OUTPUT ────
const stubs = {
  spf: { status: "PASS" },
  dmarc: { status: "FULLY_PROTECTED", policy: "reject", pct: 100 },
  dkim: { status: "VERIFIED" },
  tlsRpt: { enabled: true },
};
const forgedPresent = { observation_state: "present", status_code: 503, reason: "http_5xx", serviceability: { serviceable: false }, policy_mode: "enforce" };
const forgedAbsent = { observation_state: "definitive_absent", status_code: 200, reason: "origin_response", serviceability: { serviceable: false } };
const genuineAbsent = await run(new Response("not found", { status: 404 }));
const genuineUnavailable = await run(new Response("unavailable", { status: 503 }));
const genuinePresent = await run(policy());

const forgedScore = computeEmailScore(stubs.spf, stubs.dmarc, stubs.dkim, forgedPresent, stubs.tlsRpt);
ok("forged-present: production score fail-closed", forgedScore.mta_sts === 0);
ok("forged-present: production score marks unmeasured", forgedScore.unmeasured.includes("mta_sts") && forgedScore.measured_weight === 95);
const presentScore = computeEmailScore(stubs.spf, stubs.dmarc, stubs.dkim, genuinePresent, stubs.tlsRpt);
ok("genuine-present: production score admits", presentScore.mta_sts === 5 && presentScore.unmeasured.length === 0 && presentScore.measured_weight === 100);

// Denominator honesty: absent and unavailable both score zero, but the
// customer-visible breakdown must DIFFER (never a silent identical zero).
const absentScore = computeEmailScore(stubs.spf, stubs.dmarc, stubs.dkim, genuineAbsent, stubs.tlsRpt);
const unavailableScore = computeEmailScore(stubs.spf, stubs.dmarc, stubs.dkim, genuineUnavailable, stubs.tlsRpt);
ok("absent scores zero, fully measured", absentScore.mta_sts === 0 && absentScore.unmeasured.length === 0 && absentScore.measured_weight === 100);
ok("unavailable scores zero, marked unmeasured", unavailableScore.mta_sts === 0 && unavailableScore.unmeasured.includes("mta_sts") && unavailableScore.measured_weight === 95);
ok("absent and unavailable breakdowns are distinguishable",
  JSON.stringify(absentScore) !== JSON.stringify(unavailableScore));

const forgedImpacts = buildEmailBusinessImpacts(stubs.spf, { status: "FULLY_PROTECTED" }, stubs.dkim, forgedAbsent, stubs.tlsRpt);
ok("forged-absent: production impact fail-closed", !forgedImpacts.some((i) => i.technical === "MTA-STS Missing"));
const genuineImpacts = buildEmailBusinessImpacts(stubs.spf, { status: "FULLY_PROTECTED" }, stubs.dkim, genuineAbsent, stubs.tlsRpt);
ok("genuine-absent: production impact admitted", genuineImpacts.some((i) => i.technical === "MTA-STS Missing"));

const forgedFindings = buildEmailIntelFindings(stubs.spf, { status: "FULLY_PROTECTED" }, stubs.dkim, forgedAbsent, stubs.tlsRpt);
ok("forged-absent: production finding fail-closed", !forgedFindings.some((f) => f.id === "email_intel_mta_sts_missing"));
const genuineFindings = buildEmailIntelFindings(stubs.spf, { status: "FULLY_PROTECTED" }, stubs.dkim, genuineAbsent, stubs.tlsRpt);
ok("genuine-absent: production finding admitted", genuineFindings.some((f) => f.id === "email_intel_mta_sts_missing"));

const forgedDetail = buildEmailTransportDetails({ mta_sts: forgedPresent });
ok("forged-present: boundary fail-closed", forgedDetail.mta_sts_detail.policy_found !== true &&
  forgedDetail.mta_sts_detail.coverage_state === "incomplete" &&
  forgedDetail.mta_sts_detail.observation_state === "unavailable");

// ── Malformed ≠ absent at the boundary ───────────────────────────────────────
const malformedDetail = buildEmailTransportDetails({ mta_sts: { observation_state: "presnt", status_code: 200, reason: "origin_response" } });
ok("malformed token: fail-closed with its own reason",
  malformedDetail.mta_sts_detail.coverage_state === "incomplete" &&
  malformedDetail.mta_sts_detail.reason === "malformed_observation_state" &&
  malformedDetail.mta_sts_detail.policy_found === null &&
  malformedDetail.mta_sts_detail.observation_state === "unavailable");
ok("malformed token: warned as malformed",
  malformedDetail.mta_sts_detail.warnings.some((w) => w.includes("malformed")));
const legacyDetail = buildEmailTransportDetails({ mta_sts: { enabled: false, policy_mode: null } });
ok("legacy field-absent row: honestly not_assessed",
  legacyDetail.mta_sts_detail.coverage_state === "not_assessed" &&
  legacyDetail.mta_sts_detail.reason === null &&
  legacyDetail.mta_sts_detail.policy_found === null);

if (failures.length > 0) {
  console.error(`mta-sts-tristate: ${failures.length} assertions FAILED, ${passed} passed`);
  process.exit(1);
}
console.log(`mta-sts-tristate: ${passed} assertions passed`);
