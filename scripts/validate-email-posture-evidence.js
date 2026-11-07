#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-email-posture-evidence.js
//
// Email unknown-evidence correction for the executive posture breakdown
// (computeSecurityPosture, served by the registered /scorecard path), plus
// required SPF coverage through quality, monitoring and canonical domain/snapshot
// customer rendering.
//
// THE DEFECT. computeSecurityPosture read `!em.spf.present` / `!em.dmarc.present`
// directly, so:
//   • the deadline fallback (tri-state null presence) scored 45/critical with
//     false "publish SPF" / "publish DMARC" canonical actions;
//   • the DMARCbis compatibility projection of an unavailable core
//     (canonical not_observed) wrote dmarc.present=false, scoring 70 with a
//     false "Missing DMARC" action.
//
// THE CONTRACT. Unknown / unexecuted required evidence is neither a healthy 100
// nor a missing-record penalty. Observed absence, observed p=none, enforcing
// policies, inherited-policy compatibility, legacy (pre-ADR) reports and
// definite positive evidence keep their exact historical behaviour and canonical
// remediation identities. An optional external-RUA timeout never erases a sound
// core policy.
//
// Real producers (runEmailModule, runDmarcbisCore, the compatibility projection,
// the deadline fallback, skippedModuleResult) driven by a synthetic in-memory
// DoH zone. Every non-DoH fetch throws: zero network. Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(ROOT, "workers/scan-api/src/engines", f)).href;

// Import the engine first too: leaf coverage helpers must not introduce an
// import-order cycle through the remediation registry and domain resolver.
const { buildScanQuality } = await import(eng("scan-engine.js"));
const { computeSecurityPosture } = await import(eng("posture-scoring.js"));
const { computeScore } = await import(eng("scoring.js"));
const { isEmailProbeEvidenceUnknown, isSpfEvidenceUnknown } = await import(eng("email-evidence.js"));
const { runDnsModule } = await import(eng("dns-scan.js"));
const { deriveSignalMonitoringStates } = await import(eng("signal-monitoring-state.js"));
const { resolveSecurityCheckDomainStates, SECURITY_CHECK_RESOLVER_VERSION } = await import(eng("security-check-domains.js"));
const { composeSnapshot } = await import(eng("report-snapshot.js"));
const { enrichSpf, enrichDkim, buildEmailIntelFindings, buildEmailBusinessImpacts } = await import(eng("email-intel.js"));
const {
  applyDmarcbisEmailCompatibilityProjection,
  deadlineDeferredEmailModuleResult,
  runEmailModule,
} = await import(eng("email-scan.js"));
const {
  attachDmarcbisExternalResult,
  budgetRefusedDmarcbisExternal,
  runDmarcbisCore,
  unavailableDmarcbisCore,
} = await import(eng("dmarcbis-production.js"));
const { skippedModuleResult } = await import(eng("scan-budget.js"));

let pass = 0;
let fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) pass += 1; else fail += 1;
  console.log(`${cond ? "ok  " : "FAIL"} - ${name}${!cond && detail ? ` -- ${detail}` : ""}`);
};

// ── zero-network synthetic DoH zone ──────────────────────────────────────────
const SPF = "v=spf1 include:_spf.google.com -all";
const DMARC_REJECT = "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com";
const DMARC_NONE = "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com";
const DMARC_QUARANTINE_NO_RUA = "v=DMARC1; p=quarantine";

let ZONE = {};          // "name|TYPE" → array of TXT strings
let FAIL_NAMES = new Set();   // TXT questions answered SERVFAIL
let REFUSE_NAMES = new Set(); // TXT questions answered REFUSED
const quote = (s) => `"${s}"`;
const json = (body) => new Response(JSON.stringify(body), {
  status: 200, headers: { "content-type": "application/dns-json" },
});
globalThis.fetch = async (input) => {
  const url = new URL(String(input));
  if (!["cloudflare-dns.com", "dns.google", "dns.quad9.net"].includes(url.hostname)) {
    throw new Error(`network refused in validator: ${url.hostname}`);
  }
  const name = String(url.searchParams.get("name") || "").toLowerCase().replace(/\.$/, "");
  const type = String(url.searchParams.get("type") || "A").toUpperCase();
  if (type === "TXT" && (FAIL_NAMES.has(name) || REFUSE_NAMES.has(name))) {
    return json({ Status: REFUSE_NAMES.has(name) ? 5 : 2, Question: [{ name, type: 16 }] });
  }
  const txt = ZONE[`${name}|${type}`];
  if (type === "TXT" && txt) {
    return json({
      Status: 0,
      Question: [{ name, type: 16 }],
      Answer: txt.map((data) => ({ name, type: 16, TTL: 300, data: quote(data) })),
    });
  }
  if (name === "example.com" || name === "mail.example.com") {
    return json({ Status: 0, Question: [{ name, type: 1 }], Answer: type === "A" ? [{ name, type: 1, TTL: 300, data: "192.0.2.10" }]
      : type === "MX" ? [{ name, type: 15, TTL: 300, data: "10 mail.example.com" }] : [] });
  }
  return json({ Status: 0, Question: [{ name, type: 16 }] });
};
const zone = ({ spf = null, dmarc = null, orgDmarc = null, fail = [], refuse = [] } = {}) => {
  ZONE = {};
  if (spf) ZONE["example.com|TXT"] = [spf];
  ZONE["_spf.google.com|TXT"] = ["v=spf1 -all"];
  if (dmarc) ZONE["_dmarc.example.com|TXT"] = [dmarc];
  if (orgDmarc) ZONE["_dmarc.example.com|TXT"] = [orgDmarc];
  FAIL_NAMES = new Set(fail);
  REFUSE_NAMES = new Set(refuse);
};

// Real producer run of the scan-engine shape: email module with core-owned
// DMARC, then the one compatibility projection from the canonical core.
async function scanEmail(domain, z, { coreOverride = null } = {}) {
  zone(z);
  const email = await runEmailModule(domain, { dmarcOwnedByCore: true });
  const core = coreOverride ?? await runDmarcbisCore(domain);
  return { email: applyDmarcbisEmailCompatibilityProjection(domain, email, core), core };
}

const SC = {
  admin_surfaces: 0,
  brand_risks: { high: 0, medium: 0 },
  certificate_risks: { days_until_expiry: 365, risk_level: null },
  vendor_risk: { high: 0, medium: 0 },
  last_scanned_domain: "example.com",
  new_assets_30d: 0, saas_exposures: 0, third_party_assets: 0,
};
const postureFor = (em) => computeSecurityPosture(SC, { modules: { email_security: em } }).email_security;
// The /scorecard path reads the persisted R2 report: non-enumerable evidence
// statuses do not survive. Prove each case on the persisted shape too.
const persisted = (em) => JSON.parse(JSON.stringify(em));
const remIds = (cat) => cat.remediations.map((r) => r.remediation_id);
const reasonText = (cat) => cat.reasons.join(" | ");
const MISSING_SPF_RE = /Missing SPF/;
const MISSING_DMARC_RE = /Missing DMARC/;
const NONE_RE = /p=none/;

// Canonical remediation identities resolved by the registry (never hand-copied).
const { resolveRemediation } = await import(eng("remediation-registry.js"));
const REM = Object.fromEntries(["email_missing_spf", "email_missing_dmarc", "email_dmarc_policy_none"]
  .map((t) => [t, resolveRemediation({ finding_type: t }).remediation_id]));
ok("setup: canonical remediation identities resolve",
  Object.values(REM).every((id) => typeof id === "string" && id.length > 0), JSON.stringify(REM));

const noFalseEmailClaims = (label, cat) => {
  ok(`${label}: no Missing SPF reason`, !MISSING_SPF_RE.test(reasonText(cat)), reasonText(cat));
  ok(`${label}: no Missing DMARC reason`, !MISSING_DMARC_RE.test(reasonText(cat)), reasonText(cat));
  ok(`${label}: no missing-SPF / missing-DMARC canonical action`,
    !remIds(cat).includes(REM.email_missing_spf) && !remIds(cat).includes(REM.email_missing_dmarc),
    JSON.stringify(remIds(cat)));
};
const unknownCategory = (label, cat) => {
  ok(`${label}: score is unknown (null) — never a healthy 100, never a penalty`,
    cat.score === null && cat.status === "unknown", JSON.stringify({ score: cat.score, status: cat.status }));
  noFalseEmailClaims(label, cat);
};

// ── U. Unknown / unexecuted required evidence ────────────────────────────────
console.log("\n── U. unknown / unexecuted required evidence ──");
{
  const fb = deadlineDeferredEmailModuleResult();
  unknownCategory("U1 deadline fallback (live)", postureFor(fb));
  unknownCategory("U1 deadline fallback (persisted)", postureFor(persisted(fb)));

  const fbProjectedNull = applyDmarcbisEmailCompatibilityProjection("example.com", deadlineDeferredEmailModuleResult(), null);
  unknownCategory("U2 deadline fallback + null core projection (persisted)", postureFor(persisted(fbProjectedNull)));

  for (const reason of ["core_launch_refused", "core_deadline", "core_provider_error", "scan_deadline_exhausted"]) {
    const fbProjected = applyDmarcbisEmailCompatibilityProjection(
      "example.com", deadlineDeferredEmailModuleResult(), unavailableDmarcbisCore("example.com", reason));
    unknownCategory(`U3 deadline fallback + unavailable core (${reason}, persisted)`, postureFor(persisted(fbProjected)));
  }

  // The exact case from the defect report: SPF/DKIM present, core refused.
  const brief = applyDmarcbisEmailCompatibilityProjection(
    "example.com",
    { spf: { present: true }, dkim: { present: true } },
    unavailableDmarcbisCore("example.com", "core_launch_refused"),
  );
  ok("U4 producer: canonical state is not_observed",
    brief.dmarc_state?.enforcement_level === "not_observed", brief.dmarc_state?.enforcement_level);
  ok("U4 producer: unobserved exact lookup is presence-UNKNOWN (null), not confirmed absent (false)",
    brief.dmarc.present === null, JSON.stringify(brief.dmarc));
  for (const [label, em] of [["live", brief], ["persisted", persisted(brief)]]) {
    const cat = postureFor(em);
    unknownCategory(`U4 SPF present + core refused (${label})`, cat);
  }

  // Unavailable core on top of a real, completed email module.
  const realUnavailable = await scanEmail("example.com", { spf: SPF, dmarc: DMARC_REJECT },
    { coreOverride: unavailableDmarcbisCore("example.com", "core_deadline") });
  ok("U5 producer: real module + unavailable core → dmarc.present null",
    realUnavailable.email.dmarc.present === null, JSON.stringify(realUnavailable.email.dmarc));
  unknownCategory("U5 real SPF present + unavailable core (persisted)", postureFor(persisted(realUnavailable.email)));

  // Partial core: the exact _dmarc question itself failed.
  const partial = await scanEmail("example.com", { spf: SPF, fail: ["_dmarc.example.com"] });
  ok("U6 producer: failed exact _dmarc lookup → canonical not_observed",
    partial.email.dmarc_state?.enforcement_level === "not_observed",
    JSON.stringify({ level: partial.email.dmarc_state?.enforcement_level, core: partial.core.core_completeness }));
  ok("U6 producer: failed exact _dmarc lookup → dmarc.present null",
    partial.email.dmarc.present === null, JSON.stringify(partial.email.dmarc));
  unknownCategory("U6 failed exact _dmarc lookup (persisted)", postureFor(persisted(partial.email)));

  // Failed SPF probe inside an otherwise completed module.
  const spfFailed = await scanEmail("example.com", { dmarc: DMARC_REJECT, fail: ["example.com"] });
  ok("U7 producer: failed SPF probe → spf.present null (unknown ≠ absent)",
    spfFailed.email.spf.present === null, JSON.stringify(spfFailed.email.spf?.present));
  for (const [label, em] of [["live", spfFailed.email], ["persisted", persisted(spfFailed.email)]]) {
    const cat = postureFor(em);
    unknownCategory(`U7 failed SPF probe + enforcing DMARC (${label})`, cat);
  }

  // Errored / skipped email module.
  unknownCategory("U8 errored module (persisted)", postureFor(persisted(
    applyDmarcbisEmailCompatibilityProjection("example.com", { error: "Email module failed" }, null))));
  unknownCategory("U8 errored module with stale false presence", postureFor(
    { error: "Email module failed", spf: { present: false }, dmarc: { present: false }, dkim: { present: false } }));
  unknownCategory("U9 skipped module", postureFor(persisted(skippedModuleResult("email_security"))));
  ok("U10 unknown never adds a DKIM 'could not be verified' claim",
    !/DKIM/.test(reasonText(postureFor(persisted(deadlineDeferredEmailModuleResult())))));

  // Missing / malformed presence never proves absence. Known legacy booleans
  // remain covered by P8; these shapes have no usable boolean evidence.
  for (const present of [undefined, null, "false", 0]) {
    unknownCategory(`U11 incomplete SPF presence (${JSON.stringify(present)})`, postureFor({
      spf: { present }, dkim: { present: true }, dmarc: { present: true, policy: "reject" },
    }));
    unknownCategory(`U11 incomplete legacy DMARC presence (${JSON.stringify(present)})`, postureFor({
      spf: { present: true }, dkim: { present: true }, dmarc: { present },
    }));
  }
  unknownCategory("U11 absent SPF object", postureFor({
    dkim: { present: true }, dmarc: { present: true, policy: "reject" },
  }));
  unknownCategory("U11 explicit unavailable legacy DMARC overrides false presence", postureFor({
    spf: { present: true }, dkim: { present: true }, dmarc: { present: false },
    dmarc_evidence_status: "unavailable",
  }));
  ok("U11 incomplete DKIM presence does not invent a selector observation", !/DKIM/.test(reasonText(postureFor({
    spf: { present: true }, dkim: {}, dmarc: { present: true, policy: "reject" },
  }))));

  // No current producer emits these levels. Malformed canonical states must
  // fail closed rather than silently re-interpret the legacy presence fields.
  for (const enforcement_level of ["unknown", "future_enforced", undefined, null]) {
    unknownCategory(`U12 unsupported canonical level (${String(enforcement_level)})`, postureFor({
      spf: { present: true }, dkim: { present: true }, dmarc: { present: null },
      dmarc_state: { enforcement_level },
    }));
  }

  // The real producer's nullable SPF must remain unknown after JSON drops the
  // non-enumerable probe status. This is a consumer contract proof, not a claim
  // that stored scans are currently re-scored in the product.
  for (const [label, em] of [["live", spfFailed.email], ["persisted", persisted(spfFailed.email)]]) {
    const score = computeScore({ dns: { has_mx: true }, email_security: em }, "example.com");
    ok(`U13 nullable SPF canonical scoring (${label}): no missing-SPF finding`,
      !score.findings.some((f) => f.id === "email_missing_spf"));
    const spf = enrichSpf(em);
    const dkim = enrichDkim({ dkim: { present: true, selector: "s1" } });
    const dmarc = { status: "FULLY_PROTECTED", observation_unavailable: false };
    ok(`U13 nullable SPF enrichment (${label}): observation stays unavailable`, spf.observation_unavailable === true);
    ok(`U13 nullable SPF intel (${label}): no missing-SPF finding`,
      !buildEmailIntelFindings(spf, dmarc, dkim, { enabled: true }, { enabled: true })
        .some((f) => f.id === "email_intel_spf_missing"));
    ok(`U13 nullable SPF intel (${label}): no missing-SPF business impact`,
      !buildEmailBusinessImpacts(spf, dmarc, dkim, { enabled: true }, { enabled: true })
        .some((i) => i.technical === "SPF Missing"));
  }
}

// ── P. Positive controls: definite evidence keeps exact behaviour ────────────
console.log("\n── P. positive controls ──");
{
  // Genuine observed absence of both records — the full historical penalty.
  const absent = await scanEmail("example.com", {});
  ok("P1 producer: observed absence → spf.present false, dmarc.present false, no_record",
    absent.email.spf.present === false && absent.email.dmarc.present === false &&
      absent.email.dmarc_state?.enforcement_level === "no_record",
    JSON.stringify({ spf: absent.email.spf.present, dmarc: absent.email.dmarc, lvl: absent.email.dmarc_state?.enforcement_level, core: absent.core.core_completeness }));
  for (const [label, em] of [["live", absent.email], ["persisted", persisted(absent.email)]]) {
    const cat = postureFor(em);
    ok(`P1 observed absence (${label}): score 45 / critical`, cat.score === 45 && cat.status === "critical",
      JSON.stringify({ score: cat.score, status: cat.status }));
    ok(`P1 observed absence (${label}): both missing reasons`,
      MISSING_SPF_RE.test(reasonText(cat)) && MISSING_DMARC_RE.test(reasonText(cat)), reasonText(cat));
    ok(`P1 observed absence (${label}): canonical missing-SPF and missing-DMARC actions`,
      remIds(cat).includes(REM.email_missing_spf) && remIds(cat).includes(REM.email_missing_dmarc),
      JSON.stringify(remIds(cat)));
  }

  // Observed p=none.
  const none = await scanEmail("example.com", { spf: SPF, dmarc: DMARC_NONE });
  const noneCat = postureFor(persisted(none.email));
  ok("P2 observed p=none: score 90, monitor-only reason + canonical action",
    noneCat.score === 90 && NONE_RE.test(reasonText(noneCat)) &&
      remIds(noneCat).includes(REM.email_dmarc_policy_none) && !MISSING_DMARC_RE.test(reasonText(noneCat)),
    JSON.stringify({ score: noneCat.score, r: noneCat.reasons, rem: remIds(noneCat) }));

  const testing = await scanEmail("example.com", { spf: SPF, dmarc: "v=DMARC1; p=quarantine; t=y" });
  ok("P2 testing fixture: real canonical core lowers quarantine to monitoring",
    testing.email.dmarc_state?.enforcement_level === "monitoring" && testing.email.dmarc.policy === "quarantine");
  for (const [label, em] of [["live", testing.email], ["persisted", persisted(testing.email)]]) {
    const cat = postureFor(em);
    ok(`P2 quarantine testing (${label}): score 90, truthful testing reason + same canonical action`,
      cat.score === 90 && /p=quarantine/.test(reasonText(cat)) && /t=y/.test(reasonText(cat)) &&
        !NONE_RE.test(reasonText(cat)) && remIds(cat).includes(REM.email_dmarc_policy_none),
      JSON.stringify({ score: cat.score, r: cat.reasons, rem: remIds(cat) }));
  }

  // Enforcing policy, all present.
  const reject = await scanEmail("example.com", { spf: SPF, dmarc: DMARC_REJECT });
  const rejectCat = postureFor(persisted(reject.email));
  ok("P3 observed SPF + p=reject: healthy 100, no email actions",
    rejectCat.score === 100 && rejectCat.remediations.length === 0,
    JSON.stringify({ score: rejectCat.score, r: rejectCat.reasons, lvl: reject.email.dmarc_state?.enforcement_level }));

  // Optional external-RUA timeout must not erase a sound core policy.
  const ruaCore = await runDmarcbisCore("example.com");
  const ruaTimedOut = attachDmarcbisExternalResult(ruaCore, await budgetRefusedDmarcbisExternal(ruaCore, "provider_timeout"));
  zone({ spf: SPF, dmarc: DMARC_REJECT });
  const ruaEmail = applyDmarcbisEmailCompatibilityProjection(
    "example.com", await runEmailModule("example.com", { dmarcOwnedByCore: true }), ruaTimedOut);
  const ruaCat = postureFor(persisted(ruaEmail));
  ok("P4 external-RUA degraded: rua_authorisation is incomplete (fixture is real)",
    ruaTimedOut.rua_authorisation_completeness === "incomplete", ruaTimedOut.rua_authorisation_completeness);
  ok("P4 external-RUA degraded: canonical policy retained, dmarc.present true",
    ruaEmail.dmarc_state?.enforcement_level === "reject_enforced" && ruaEmail.dmarc.present === true,
    JSON.stringify({ lvl: ruaEmail.dmarc_state?.enforcement_level, dmarc: ruaEmail.dmarc }));
  ok("P4 external-RUA degraded: posture stays 100 (sound core policy not erased)",
    ruaCat.score === 100, JSON.stringify({ score: ruaCat.score, r: ruaCat.reasons }));

  // A real SPF absence is never hidden because DMARC evidence is unknown.
  const mixed = await scanEmail("example.com", {}, {
    coreOverride: unavailableDmarcbisCore("example.com", "core_deadline"),
  });
  const mixedCat = postureFor(persisted(mixed.email));
  ok("P5 observed SPF absence + unknown DMARC: SPF penalty and action kept, no DMARC claim",
    mixedCat.score === 75 && MISSING_SPF_RE.test(reasonText(mixedCat)) &&
      remIds(mixedCat).includes(REM.email_missing_spf) &&
      !MISSING_DMARC_RE.test(reasonText(mixedCat)) && !remIds(mixedCat).includes(REM.email_missing_dmarc),
    JSON.stringify({ score: mixedCat.score, r: mixedCat.reasons, rem: remIds(mixedCat) }));

  // Observed p=none with an unknown SPF probe keeps its p=none finding.
  const noneSpfFail = await scanEmail("example.com", { dmarc: DMARC_NONE, fail: ["example.com"] });
  const noneSpfFailCat = postureFor(persisted(noneSpfFail.email));
  ok("P6 observed p=none + unknown SPF: p=none penalty and action kept, no SPF claim",
    noneSpfFailCat.score === 90 && remIds(noneSpfFailCat).includes(REM.email_dmarc_policy_none) &&
      !MISSING_SPF_RE.test(reasonText(noneSpfFailCat)),
    JSON.stringify({ score: noneSpfFailCat.score, r: noneSpfFailCat.reasons }));

  // Inherited policy: exact _dmarc.mail.example.com absent (a COMPLETE, confirmed
  // exact absence), organisational policy at _dmarc.example.com. Posture follows
  // the one persisted compatibility state, exactly as the canonical numeric
  // score (scoring.js) does — no second DMARC interpretation.
  zone({ spf: SPF });
  ZONE["_dmarc.example.com|TXT"] = [DMARC_QUARANTINE_NO_RUA];
  const inhCore = await runDmarcbisCore("mail.example.com");
  ok("P7 fixture: real complete core, organisational source, exact domain absent",
    inhCore.core_completeness === "complete" && inhCore.policy_source_kind === "organisational" &&
      inhCore.observation_state === "absent",
    JSON.stringify({ core: inhCore.core_completeness, kind: inhCore.policy_source_kind, obs: inhCore.observation_state }));
  const inhEmail = applyDmarcbisEmailCompatibilityProjection(
    "mail.example.com", { spf: { present: true }, dkim: { present: true } }, inhCore);
  const inhCat = postureFor(persisted(inhEmail));
  ok("P7 v2 inherited: exact absence stays CONFIRMED (present false, record_count 0)",
    inhEmail.dmarc.present === false && inhEmail.dmarc.record_count === 0, JSON.stringify(inhEmail.dmarc));
  ok("P7 v2 inherited: posture follows the persisted state — no missing-DMARC claim for an inherited policy",
    !MISSING_DMARC_RE.test(reasonText(inhCat)) && !remIds(inhCat).includes(REM.email_missing_dmarc) &&
      inhCat.score !== 100,
    JSON.stringify({ lvl: inhEmail.dmarc_state?.enforcement_level, score: inhCat.score, rem: remIds(inhCat) }));

  // Legacy (non-v2) policy evidence keeps the shipped exact-record bridge: a
  // complete walk with no exact record is the compatibility no_record → the
  // historical missing-DMARC penalty and canonical action are unchanged.
  const legacyInh = applyDmarcbisEmailCompatibilityProjection(
    "mail.example.com", { spf: { present: true }, dkim: { present: true } },
    { ...inhCore, schema: "dmarc-policy.v1" });
  const legacyInhCat = postureFor(persisted(legacyInh));
  ok("P7 legacy-schema inherited: exact-record bridge → no_record, present false",
    legacyInh.dmarc_state?.enforcement_level === "no_record" && legacyInh.dmarc.present === false,
    JSON.stringify({ lvl: legacyInh.dmarc_state?.enforcement_level, dmarc: legacyInh.dmarc }));
  ok("P7 legacy-schema inherited: missing-DMARC rule unchanged (score 70, canonical action)",
    legacyInhCat.score === 70 && remIds(legacyInhCat).includes(REM.email_missing_dmarc),
    JSON.stringify({ score: legacyInhCat.score, rem: remIds(legacyInhCat) }));

  // Legacy pre-ADR reports (no dmarc_state, boolean presence) keep the raw read.
  const legacy = (spf, dmarc, policy = null) => postureFor({
    spf: { present: spf }, dmarc: { present: dmarc, policy }, dkim: { present: true },
  });
  ok("P8 legacy present/present p=reject → 100", legacy(true, true, "reject").score === 100);
  ok("P8 legacy present/present p=none → 90 + monitor-only action",
    legacy(true, true, "none").score === 90 && remIds(legacy(true, true, "none")).includes(REM.email_dmarc_policy_none));
  ok("P8 legacy absent/absent → 45 + both actions",
    legacy(false, false).score === 45 &&
      remIds(legacy(false, false)).includes(REM.email_missing_spf) &&
      remIds(legacy(false, false)).includes(REM.email_missing_dmarc));
  ok("P8 legacy observed DKIM non-detection still reported informationally",
    /DKIM/.test(reasonText(postureFor({ spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: false } }))));
  ok("P9 no email module at all → null (unchanged)",
    computeSecurityPosture(SC, { modules: {} }).email_security.score === null);

  // The nullable consumer correction must preserve genuine producer absence
  // and the known pre-status legacy booleans in both canonical SPF consumers.
  const spfControls = [
    ["producer live absence", absent.email, false],
    ["producer persisted absence", persisted(absent.email), false],
    ["legacy false", { spf: { present: false, record: null }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } }, false],
    ["legacy true", { spf: { present: true, record: "v=spf1 -all" }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } }, true],
  ];
  for (const [label, em, present] of spfControls) {
    const score = computeScore({ dns: { has_mx: true }, email_security: em }, "example.com");
    ok(`P10 SPF ${label}: canonical missing finding matches known boolean`,
      score.findings.some((f) => f.id === "email_missing_spf") === !present);
    const spf = enrichSpf(em);
    ok(`P10 SPF ${label}: enrichment retains observed presence/absence`,
      present ? spf.status === "PASS" : spf.status === "MISSING" && spf.observation_unavailable === false);
  }
}

// ── C. Required SPF coverage through actual producers and customer surfaces ──
// Real DNS/email/core producers above; the supplementary module is a declared
// complete stub so this bounded proof isolates the primary SPF coverage gate.
// This is not an admitted full runScanEngine or production-persistence proof.
console.log("\n── C. required SPF coverage: producers → quality/monitoring/domain/snapshot/render ──");
{
  const workerRequire = createRequire(path.join(ROOT, "workers/scan-api/package.json"));
  const frontendRequire = createRequire(path.join(ROOT, "frontend/package.json"));
  const { buildSync } = workerRequire("esbuild");
  const React = frontendRequire("react");
  const { renderToStaticMarkup } = frontendRequire("react-dom/server");
  const compiled = buildSync({
    entryPoints: [path.join(ROOT, "frontend/src/components/SecurityCheckDomains.jsx")],
    bundle: true, platform: "node", format: "cjs", write: false,
    external: ["react"], logLevel: "silent",
  }).outputFiles[0].text;
  const componentModule = { exports: {} };
  new Function("require", "module", "exports", compiled)(frontendRequire, componentModule, componentModule.exports);
  const SecurityCheckDomains = componentModule.exports.default;
  const renderEmail = (domains) => {
    const html = renderToStaticMarkup(React.createElement(SecurityCheckDomains, { domains }));
    // Keep the real Email row, excluding the next domain and its conclusion.
    return html.split('>Email Protection</div>')[1]?.split('>Attack Surface</div>')[0] || "";
  };
  const reportFor = (email, core, dns) => {
    const modules = { dns, email_security: email, dmarc_core: core, email_security_intelligence: {} };
    const scored = computeScore(modules, "example.com");
    return {
      domain: "example.com", scan_id: "synthetic-spf-coverage", completed_at: "2026-11-07T12:00:00.000Z",
      modules, findings: scored.findings, recommendations: scored.recommendations,
      cyber_metrics_score: scored.score, scan_quality: buildScanQuality(modules),
      monitoring_states: deriveSignalMonitoringStates({ modules }),
    };
  };
  const snapshotFor = (report) => composeSnapshot({
    snapshotId: "synthetic-spf-snapshot", workspaceId: "synthetic-workspace", domainId: "synthetic-domain",
    scanId: report.scan_id, domain: report.domain, report,
    cyberEssentials: null, ceReadiness: null, caseRows: [], questionSetVersions: [],
    builtAt: "2026-11-07T12:00:01.000Z",
  });
  const cases = [
    ["observed SPF + enforcing DMARC", { spf: SPF, dmarc: DMARC_REJECT }, "complete", "assessed_healthy"],
    ["SPF present + include lookup unavailable", { spf: SPF, dmarc: DMARC_REJECT, fail: ["_spf.google.com"] }, "complete", "assessed_healthy"],
    ["SPF SERVFAIL + enforcing independent DMARC", { dmarc: DMARC_REJECT, fail: ["example.com"] }, "partial", "evidence_insufficient"],
    // Captured legacy producer shape: b3ef13a7f4ff82a3be2be708dd10f82b50cfcf42
    // email-scan.js assigned hasSPF=false after a failed root lookup while its
    // SPF authorisation fallback recorded temperror. Reuse the real current
    // producer module, changing only that historical presence field; a local
    // diagnostic separately executes the immutable old producer source.
    ["legacy false SPF root failure + enforcing independent DMARC", { dmarc: DMARC_REJECT, fail: ["example.com"] }, "partial", "evidence_insufficient", "legacy-root-failed"],
    ["legacy false SPF root failure + observed DMARC issue", { dmarc: DMARC_NONE, fail: ["example.com"] }, "partial", "issue_detected", "legacy-root-failed"],
    ["SPF REFUSED + enforcing independent DMARC", { dmarc: DMARC_REJECT, refuse: ["example.com"] }, "partial", "evidence_insufficient"],
    ["SPF not run + enforcing independent DMARC", { spf: SPF, dmarc: DMARC_REJECT }, "partial", "evidence_insufficient", "not-run"],
    ["whole email module deferred + independently observed DMARC issue", { dmarc: DMARC_NONE }, "partial", "issue_detected", "not-run"],
    ["observed SPF absence + enforcing DMARC", { dmarc: DMARC_REJECT }, "complete", "issue_detected"],
    ["SPF unknown + observed DMARC issue", { dmarc: DMARC_NONE, fail: ["example.com"] }, "partial", "issue_detected"],
    ["optional external RUA timeout", { spf: SPF, dmarc: DMARC_REJECT }, "complete", "assessed_healthy", "optional-rua"],
  ];
  for (const [name, z, expectedQuality, expectedState, variant] of cases) {
    let { email, core } = await scanEmail("example.com", z);
    const dns = await runDnsModule("example.com");
    if (variant === "legacy-root-failed") {
      const status = email.spf_evidence_status;
      email = { ...email, spf: { ...email.spf, present: false } };
      Object.defineProperty(email, "spf_evidence_status", { value: status, enumerable: false });
      ok(`C ${name}: exact persisted legacy root-failure marker`,
        email.spf.present === false && email.spf.record === null && email.spf.record_count === 0 &&
        email.spf.resolution_status === "temperror" && email.spf.resolved_pass_authorisations === null);
    }
    if (variant === "not-run") {
      email = applyDmarcbisEmailCompatibilityProjection("example.com", deadlineDeferredEmailModuleResult(), core);
    }
    if (variant === "optional-rua") {
      core = attachDmarcbisExternalResult(core, await budgetRefusedDmarcbisExternal(core, "provider_timeout"));
      email = applyDmarcbisEmailCompatibilityProjection("example.com", email, core);
    }
    ok(`C ${name}: actual DNS A/MX evidence remains usable`,
      dns.has_mx === true && dns.resolution_assessed === true && dns.resolves === true, JSON.stringify(dns));
    ok(`C ${name}: independent DMARC conclusion retained`,
      email.dmarc_state?.enforcement_level === (z.dmarc === DMARC_NONE ? "monitoring" : "reject_enforced"));
    for (const [shape, em] of [["live", email], ["JSON", persisted(email)]]) {
      const label = `C ${name} (${shape})`;
      const liveReport = reportFor(em, core, dns);
      const report = shape === "JSON" ? persisted(liveReport) : liveReport;
      const beforeCoverage = JSON.stringify(report.modules.email_security);
      if (variant === "legacy-root-failed") {
        const category = postureFor(report.modules.email_security);
        if (z.dmarc === DMARC_REJECT) unknownCategory(`${label}: legacy root failure posture`, category);
        else ok(`${label}: known DMARC posture deduction retained, no false SPF action`,
          category.score === 90 && remIds(category).includes(REM.email_dmarc_policy_none) &&
          !remIds(category).includes(REM.email_missing_spf));
        const spf = enrichSpf(report.modules.email_security);
        const dkim = enrichDkim({ dkim: { present: true, selector: "s1" } });
        const dmarc = { status: "FULLY_PROTECTED", observation_unavailable: false };
        ok(`${label}: legacy SPF enrichment marks observation unavailable`, spf.observation_unavailable === true);
        ok(`${label}: no false legacy missing-SPF intelligence finding or impact`,
          !buildEmailIntelFindings(spf, dmarc, dkim, { enabled: true }, { enabled: true })
            .some((f) => f.id === "email_intel_spf_missing") &&
          !buildEmailBusinessImpacts(spf, dmarc, dkim, { enabled: true }, { enabled: true })
            .some((i) => i.technical === "SPF Missing"));
      }
      if (variant === "legacy-root-failed" && shape === "JSON") {
        // Captured pre-correction report metadata said complete/healthy even
        // though the producer recorded the root failure. A current raw-report
        // read must recognise that marker without editing the stored bytes.
        const stored = persisted(reportFor(email, core, dns));
        stored.scan_quality = { status: "complete", warnings: [], degradations: [], modules_skipped: [], modules_incomplete: [] };
        stored.monitoring_states.signals.email_protection.state = "monitoring_healthy";
        const storedBytes = JSON.stringify(stored);
        const readDomain = resolveSecurityCheckDomainStates(stored).find((d) => d.domain_key === "email_protection");
        const readSnapshot = snapshotFor(stored).domains.find((d) => d.domain_key === "email_protection");
        ok(`${label}: raw legacy whole-report read rejects its old healthy metadata`,
          readDomain.state === expectedState && readSnapshot.state === expectedState &&
          (z.dmarc !== DMARC_NONE || readDomain.coverage === "partial"));
        ok(`${label}: raw legacy read leaves stored report bytes unchanged`, JSON.stringify(stored) === storedBytes);
      }
      const domains = resolveSecurityCheckDomainStates(report);
      const domain = domains.find((d) => d.domain_key === "email_protection");
      const snapshot = snapshotFor(report);
      const frozen = snapshot.domains.find((d) => d.domain_key === "email_protection");
      ok(`${label}: coverage readers preserve producer evidence`,
        JSON.stringify(report.modules.email_security) === beforeCoverage);
      if (name.includes("include lookup")) {
        ok(`${label}: only the include resolution failed, root SPF remains observed`,
          em.spf.present === true && em.spf.resolution_status === "temperror");
      }
      // Keep the expected vocabulary statically governed; both branches assert
      // the real recorded status, never a test-only normalized replacement.
      if (expectedQuality === "complete") {
        ok(`${label}: scan quality complete`, report.scan_quality.status === "complete", JSON.stringify(report.scan_quality));
      } else if (expectedQuality === "partial") {
        ok(`${label}: scan quality partial`, report.scan_quality.status === "partial", JSON.stringify(report.scan_quality));
      } else {
        throw new Error(`Unexpected coverage fixture quality: ${expectedQuality}`);
      }
      const expectedMonitoring = expectedQuality === "partial" ? "evidence_incomplete"
        : variant === "optional-rua" ? "monitoring_degraded" : "monitoring_healthy";
      ok(`${label}: monitoring ${expectedMonitoring}`,
        report.monitoring_states.signals.email_protection.state === expectedMonitoring,
        JSON.stringify(report.monitoring_states.signals.email_protection));
      ok(`${label}: canonical domain ${expectedState}`, domain.state === expectedState, JSON.stringify(domain));
      ok(`${label}: frozen snapshot matches canonical domain and methodology`,
        frozen.state === expectedState && frozen.coverage === domain.coverage &&
        snapshot.methodology?.cyber_mot_resolver_version === SECURITY_CHECK_RESOLVER_VERSION,
        JSON.stringify({ frozen, methodology: snapshot.methodology }));
      const expectedLabel = { assessed_healthy: "Healthy", evidence_insufficient: "Evidence insufficient", issue_detected: "Issue detected" }[expectedState];
      for (const [surface, entries] of [["resolved", domains], ["snapshot JSON", persisted(snapshot).domains]]) {
        const html = renderEmail(entries);
        ok(`${label}: actual ${surface} component renders ${expectedLabel}`,
          html.includes(expectedLabel) && (expectedState === "assessed_healthy" || !html.includes('>Healthy<')), html);
      }
      ok(`${label}: SPF finding reflects observed absence only`,
        report.findings.some((f) => f.id === "email_missing_spf") === (expectedQuality === "complete" && email.spf.present === false));
      if (expectedQuality === "partial") {
        ok(`${label}: quality names incomplete email evidence`,
          report.scan_quality.modules_incomplete.some((m) => m.module === "email_security"));
        ok(`${label}: no missing-SPF action for unknown SPF`,
          !em.remediation_actions.some((a) => a.id === "spf_missing") &&
          !snapshot.observed_findings.some((f) => f.finding_id === "email_missing_spf"));
      }
      if (z.dmarc === DMARC_NONE) {
        ok(`${label}: observed DMARC finding + canonical action survive partial SPF coverage`,
          domain.coverage === "partial" && frozen.coverage === "partial" &&
          report.findings.some((f) => f.id === "email_dmarc_policy_none") &&
          report.recommendations.some((a) => a.module === "email_security") &&
          (variant === "not-run" || em.remediation_actions.some((a) => a.id === "dmarc_policy_monitoring_only")) &&
          snapshot.observed_findings.some((f) => f.finding_id === "email_dmarc_policy_none") &&
          frozen.remediation_ids.includes(REM.email_dmarc_policy_none) &&
          snapshot.remediation_actions.some((a) => a.remediation_id === REM.email_dmarc_policy_none), JSON.stringify(frozen));
      }
    }
  }
}

// The root marker does not depend on unrelated nullable counters. The original
// two-argument classifier remains the generic presence/status API (including DKIM).
{
  const rootFailure = { present: false, record: null, record_count: 0, resolution_status: "temperror" };
  const email = { spf: rootFailure, dkim: { present: true }, dmarc: { present: true, policy: "reject" } };
  unknownCategory("C legacy minimal root-probe marker", postureFor(email));
  ok("C legacy minimal root-probe marker needs no optional lookup counters",
    isSpfEvidenceUnknown(rootFailure) === true && enrichSpf(email).observation_unavailable === true &&
    buildScanQuality({ email_security: email }).status === "partial");
  ok("C generic two-argument presence/status API remains unchanged",
    isEmailProbeEvidenceUnknown(false) === false && isEmailProbeEvidenceUnknown(true) === false &&
    isEmailProbeEvidenceUnknown(false, "unavailable") === true &&
    isEmailProbeEvidenceUnknown(true, "not_yet_assessed") === true);
}

// Generic status fragments are not the captured legacy root-probe marker.
// Existing boolean compatibility and the generic DKIM API must remain intact.
for (const [name, spf] of [
  ["plain boolean false", { present: false }],
  ["generic temperror", { present: false, resolution_status: "temperror" }],
  ["missing record count", { present: false, record: null, resolution_status: "temperror" }],
  ["missing record value", { present: false, record_count: 0, resolution_status: "temperror" }],
  ["non-numeric count", { present: false, record: null, record_count: "0", resolution_status: "temperror" }],
]) {
  const email = { spf, dkim: { present: true }, dmarc: { present: true, policy: "reject" } };
  const scored = computeScore({ dns: { has_mx: true }, email_security: email }, "example.com");
  ok(`C compatibility ${name}: known boolean absence keeps its finding, action and complete coverage`,
    scored.findings.some((f) => f.id === "email_missing_spf") &&
    remIds(postureFor(email)).includes(REM.email_missing_spf) &&
    enrichSpf(email).observation_unavailable === false &&
    buildScanQuality({ email_security: email }).status === "complete");
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
