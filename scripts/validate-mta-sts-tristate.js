#!/usr/bin/env node
// MTA-STS tri-state contract (and, below, the TLS-RPT TXT evidence contract):
// producer coherence, canonical admission, and the PRODUCTION consumer paths
// (score, business impacts, findings, transport
// boundary). Forged evidence must fail closed at every consumer OUTPUT, and a
// zero from unavailable evidence must never be byte-identical to a zero from
// admitted absence (denominator honesty).
import {
  fetchMtaSts,
  computeEmailScore,
  buildEmailBusinessImpacts,
  buildEmailIntelFindings,
  runEmailIntelModule,
} from "../workers/scan-api/src/engines/email-intel.js";
import {
  mtaStsAdmission,
  buildEmailTransportDetails,
  buildEmailRemediationActions,
  parseTlsRptAnswers,
  tlsRptAdmission,
} from "../workers/scan-api/src/engines/email-analysis.js";
import { runEmailModule } from "../workers/scan-api/src/engines/email-scan.js";

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

// ── Canonical-authority eligibility: conclusion_class matters ────────────────
// A serviceable-true record whose conclusion class is NOT "conclusive" admits
// nothing. A private `serviceable === true` re-check would pass these probes —
// this is the binding-rule assertion that kills that private predicate.
const nonConclusive = { serviceable: true, conclusion_class: "evidence_insufficient", reason: "origin_informational_only", origin_status: 200 };
const ncPresent = mtaStsAdmission({ observation_state: "present", status_code: 200, reason: "origin_response", serviceability: nonConclusive });
ok("conclusive-class gate: serviceable-true non-conclusive present is not admitted",
  ncPresent.state === "unavailable" && !ncPresent.score_admitted);
const ncAbsent = mtaStsAdmission({ observation_state: "definitive_absent", status_code: 404, reason: "well_known_404", serviceability: nonConclusive });
ok("conclusive-class gate: serviceable-true non-conclusive absence is not admitted",
  ncAbsent.state === "unavailable" && !ncAbsent.missing_finding && !ncAbsent.remediation_admitted);

// ── Body-read failure (ADV-2b path): 200 arrives, the body read throws ───────
// enabled must be false AFTER the catch regardless of any pre-set state, and the
// outcome is unavailable with a shaped serviceability.
const bodyReadFailure = await (async () => {
  const fetcher = async () => {
    // A REAL 200 Response (so classification and the absence-grounding gate all
    // pass and execution genuinely reaches the body read), whose body read throws.
    const res = new Response("version: STSv1\n", { status: 200 });
    res.text = async () => { throw Object.assign(new Error("body stream reset"), { name: "TypeError" }); };
    return res;
  };
  return fetchMtaSts("example.com", { fetcher });
})();
ok("body-read-failure: observation state", bodyReadFailure.observation_state === "unavailable");
ok("body-read-failure: enabled coherence", bodyReadFailure.enabled === false);
ok("body-read-failure: serviceability shape",
  bodyReadFailure.serviceability !== null && typeof bodyReadFailure.serviceability === "object" &&
  bodyReadFailure.serviceability.serviceable === false);

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
const genuineFindings = buildEmailIntelFindings(stubs.spf, { status: "FULLY_PROTECTED" }, stubs.dkim, genuineAbsent, stubs.tlsRpt, "cybermeters.com");
ok("missing MTA-STS names the actual domain", genuineFindings.find((f) => f.id === "email_intel_mta_sts_missing")?.description.includes("https://mta-sts.cybermeters.com/.well-known/mta-sts.txt"));
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

// ── Orchestrator breakdown pin: the denominator markers reach the customer ───
// Full runEmailIntelModule with an injected 503 MTA-STS fetch (TLS-RPT's DNS
// lookup is forced onto its own error path — no live network in this validator).
const orchestratorResult = await (async () => {
  const savedFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("network disabled in validator"); };
  try {
    return await runEmailIntelModule("example.com", {}, {}, {
      fetcher: async () => new Response("unavailable", { status: 503 }),
    });
  } finally {
    globalThis.fetch = savedFetch;
  }
})();
ok("orchestrator breakdown carries denominator markers",
  Array.isArray(orchestratorResult.email_score_breakdown.unmeasured) &&
  orchestratorResult.email_score_breakdown.unmeasured.includes("mta_sts") &&
  // TLS-RPT's lookup throws here too, so it is unmeasured as well (27 Oct 2026):
  // a failed DNS query is not a measured TLS-RPT zero.
  orchestratorResult.email_score_breakdown.unmeasured.includes("tls_rpt") &&
  orchestratorResult.email_score_breakdown.measured_weight === 90);
ok("orchestrator mta_sts outcome is unavailable, not absence",
  orchestratorResult.mta_sts.observation_state === "unavailable" &&
  orchestratorResult.email_score_breakdown.mta_sts === 0);

// Hardening (24 Oct 2026): the built-in fetcher resolves the policy host first.
// A policy host resolving to a private address gets DNS lookups only, never an
// HTTP request, and is never read as an enforced policy.
{
  let dns = 0, http = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const u = String(input?.url || input);
    if (/dns-query|resolve\?name=|cloudflare-dns|dns\.google|quad9/.test(u)) {
      dns++;
      const params = new URL(u).searchParams;
      const name = params.get("name") || "x", type = params.get("type") || "A";
      const Answer = type === "A" ? [{ name, type: 1, TTL: 60, data: "10.0.0.7" }] : [];
      return new Response(JSON.stringify({ Status: 0, Answer }), { status: 200, headers: { "content-type": "application/dns-json" } });
    }
    http++;
    return new Response("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n", { status: 200 });
  };
  let r;
  try { r = await fetchMtaSts("private-policy.com"); } finally { globalThis.fetch = originalFetch; }
  ok("MTA-STS private-resolving policy host: DNS consulted", dns > 0);
  ok("MTA-STS private-resolving policy host: no HTTP request", http === 0);
  ok("MTA-STS private-resolving policy host: never an enforced policy", r?.enabled === false && r?.policy_mode !== "enforce");
}

// ── TLS-RPT TXT evidence (P2, 27 Oct 2026) ──────────────────────────────────────
// DNS JSON returns a TXT value as quoted character-strings, so the published record
// "v=TLSRPTv1; rua=…" arrives as "\"v=TLSRPTv1; rua=…\"". checkTlsRpt compared the
// raw string, so a real record read as missing and the customer was told to publish
// one; a failed or inconclusive lookup also read as missing. These cases drive the
// production path — runEmailModule -> runEmailIntelModule -> checkTlsRpt (real
// dnsQuery and DNS cache) -> buildEmailTransportDetails ->
// buildEmailRemediationActions, wired as scan-engine.js does — against a local
// DNS-over-HTTPS stub. No live network.
{
  const DOMAIN = "fixture.example";
  const TLS_NAME = `_smtp._tls.${DOMAIN}`;
  const RECORD = "v=TLSRPTv1; rua=mailto:tls@fixture.example";
  const TXT = 16;
  const txt = (data, type = TXT) => ({ name: TLS_NAME, type, TTL: 300, data });
  const noerror = (Answer) => ({ Status: 0, TC: false, Answer });

  // One scan run: every DoH question is answered locally. SPF and DMARC are
  // published so the email evidence is publishable and actions are built; the
  // TLS-RPT name gets the case's answer (an object, a throw, or an HTTP error).
  async function scan(tlsAnswer) {
    const saved = globalThis.fetch;
    globalThis.fetch = async (input) => {
      const url = new URL(typeof input === "string" ? input : input.url);
      const name = (url.searchParams.get("name") || "").toLowerCase();
      const type = (url.searchParams.get("type") || "").toUpperCase();
      let body;
      if (name === TLS_NAME) {
        if (tlsAnswer === "throw") throw new TypeError("network unavailable");
        if (tlsAnswer === "http_503") return new Response("busy", { status: 503 });
        body = tlsAnswer;
      } else if (name === DOMAIN && type === "TXT") {
        body = noerror([{ name: DOMAIN, type: TXT, TTL: 300, data: "\"v=spf1 -all\"" }]);
      } else if (name === `_dmarc.${DOMAIN}` && type === "TXT") {
        body = noerror([{ name: `_dmarc.${DOMAIN}`, type: TXT, TTL: 300, data: "\"v=DMARC1; p=reject; rua=mailto:d@fixture.example\"" }]);
      } else {
        body = { Status: 3, TC: false };
      }
      return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/dns-json" } });
    };
    try {
      const cache = new Map();
      const email = await runEmailModule(DOMAIN, { cache });
      const intel = await runEmailIntelModule(DOMAIN, email, {}, {
        cache,
        fetcher: async () => new Response("not found", { status: 404 }),
      });
      Object.assign(email, buildEmailTransportDetails(intel));
      const actions = buildEmailRemediationActions(DOMAIN, email, intel);
      return { intel, detail: email.tls_rpt_detail, actions };
    } finally {
      globalThis.fetch = saved;
    }
  }

  const publishAdvice = (r) => r.actions.some((a) => a.id === "tls_rpt_missing");
  const missingFinding = (r) => (r.intel.findings || []).some((f) => f.id === "email_intel_tls_rpt_missing");
  const missingImpact = (r) => (r.intel.business_impacts || []).some((i) => i.technical === "TLS-RPT Missing");

  // ── Present: quoted, split into chunks, and the legacy unquoted shape ───────────
  for (const [label, data] of [
    ["quoted", JSON.stringify(RECORD)],
    ["split into two character-strings", "\"v=TLSRPTv1; \" \"rua=mailto:tls@fixture.example\""],
    ["unquoted", RECORD],
  ]) {
    const r = await scan(noerror([txt(data)]));
    ok(`${label}: record found and enabled`, r.intel.tls_rpt.enabled === true && r.detail.record_found === true &&
      r.detail.observation_state === "present" && r.detail.coverage_state === "complete");
    ok(`${label}: record normalised and rua read`, r.intel.tls_rpt.record === RECORD &&
      JSON.stringify(r.detail.rua) === JSON.stringify(["mailto:tls@fixture.example"]));
    ok(`${label}: no publish advice, finding or impact; scored`, !publishAdvice(r) && !missingFinding(r) && !missingImpact(r) &&
      r.intel.email_score_breakdown.tls_rpt === 5 && !r.intel.email_score_breakdown.unmeasured.includes("tls_rpt"));
  }

  // ── Conclusive "no valid record": NOERROR/NODATA, NXDOMAIN, wrong version, invalid ─
  for (const [label, answer, reason] of [
    ["NOERROR with no answers", noerror([]), "no_txt_record"],
    ["NXDOMAIN", { Status: 3, TC: false }, "no_txt_record"],
    ["wrong version v=TLSRPTv12", noerror([txt(JSON.stringify("v=TLSRPTv12; rua=mailto:tls@fixture.example"))]), "no_tls_rpt_record"],
    ["unrelated TXT", noerror([txt(JSON.stringify("google-site-verification=abc"))]), "no_tls_rpt_record"],
    ["version without a field separator", noerror([txt(JSON.stringify("v=TLSRPTv1 rua=mailto:tls@fixture.example"))]), "no_tls_rpt_record"],
    ["record without rua", noerror([txt(JSON.stringify("v=TLSRPTv1;"))]), "missing_rua"],
    ["two TLS-RPT records", noerror([txt(JSON.stringify(RECORD)), txt(JSON.stringify("v=TLSRPTv1; rua=mailto:other@fixture.example"))]), "multiple_records"],
  ]) {
    const r = await scan(answer);
    ok(`${label}: conclusively no valid record`, r.intel.tls_rpt.enabled === false && r.detail.record_found === false &&
      r.detail.observation_state === "definitive_absent" && r.detail.coverage_state === "complete" && r.intel.tls_rpt.reason === reason);
    ok(`${label}: publish advice, finding and impact are admitted; measured zero`, publishAdvice(r) && missingFinding(r) && missingImpact(r) &&
      r.intel.email_score_breakdown.tls_rpt === 0 && !r.intel.email_score_breakdown.unmeasured.includes("tls_rpt"));
  }

  // ── Not concluded: SERVFAIL, REFUSED, HTTP error, throw, malformed replies ─────────
  for (const [label, answer] of [
    ["SERVFAIL (Status 2) with no answers", { Status: 2, TC: false }],
    ["REFUSED (Status 5)", { Status: 5, TC: false }],
    ["SERVFAIL carrying a record", { Status: 2, TC: false, Answer: [txt(JSON.stringify(RECORD))] }],
    ["DoH HTTP 503", "http_503"],
    ["resolver throws", "throw"],
    ["reply without Status", { Answer: [] }],
    ["Answer is not an array", { Status: 0, Answer: { data: RECORD } }],
    ["resolver disagreement", { Status: 0, resolver_agreement: "disagreement", Answer: [] }],
  ]) {
    const r = await scan(answer);
    ok(`${label}: unknown, never "not found"`, r.intel.tls_rpt.enabled === false && r.detail.record_found === null &&
      r.detail.observation_state === "unavailable" && r.detail.coverage_state === "incomplete");
    ok(`${label}: no publish advice, finding or impact`, !publishAdvice(r) && !missingFinding(r) && !missingImpact(r));
    ok(`${label}: no healthy result; zero is unmeasured, not measured`, r.intel.email_score_breakdown.tls_rpt === 0 &&
      r.intel.email_score_breakdown.unmeasured.includes("tls_rpt") &&
      !(r.intel.strengths || []).some((s) => /TLS-RPT configured/.test(s)));
    ok(`${label}: says it could not be verified`, r.detail.warnings.some((w) => /could not be verified/.test(w)));
  }

  // ── Only TXT answers count ──────────────────────────────────────────────────────
  {
    const r = await scan(noerror([{ name: TLS_NAME, type: 5, TTL: 300, data: "elsewhere.fixture.example." }, txt(JSON.stringify(RECORD), 99)]));
    ok("a CNAME and a non-TXT record carrying the value are not a TLS-RPT record",
      r.intel.tls_rpt.enabled === false && r.detail.observation_state === "definitive_absent");
  }
  ok("parser ignores answers without a TXT type", parseTlsRptAnswers([{ data: RECORD }]).valid === false);

  // ── Admission keeps older rows and refuses incoherent ones ─────────────────────
  ok("row from before observation_state: enabled reads present", tlsRptAdmission({ enabled: true }).state === "present");
  ok("row from before observation_state: not enabled reads absent", tlsRptAdmission({ enabled: false }).state === "definitive_absent");
  ok("no row at all is not observed, admits nothing", (() => {
    const a = tlsRptAdmission(undefined);
    return a.state === "not_observed" && !a.missing_finding && !a.remediation_admitted && !a.score_admitted;
  })());
  ok("present token without an enabled record is refused", tlsRptAdmission({ observation_state: "present", enabled: false }).state === "unavailable");
  ok("absent token on an enabled row is refused", tlsRptAdmission({ observation_state: "definitive_absent", enabled: true }).state === "unavailable");
  ok("unknown token is refused", tlsRptAdmission({ observation_state: "healthy", enabled: true, record: RECORD }).state === "unavailable");
  ok("no TLS-RPT row: transport detail is not assessed, never not found", (() => {
    const d = buildEmailTransportDetails({}).tls_rpt_detail;
    return d.record_found === null && d.coverage_state === "not_assessed";
  })());
}

if (failures.length > 0) {
  console.error(`mta-sts-tristate: ${failures.length} assertions FAILED, ${passed} passed`);
  process.exit(1);
}
console.log(`mta-sts-tristate: ${passed} assertions passed`);
