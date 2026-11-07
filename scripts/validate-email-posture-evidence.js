#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-email-posture-evidence.js
//
// Email unknown-evidence correction for the executive posture breakdown
// (computeSecurityPosture, served by the registered /scorecard path).
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
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(ROOT, "workers/scan-api/src/engines", f)).href;

const { computeSecurityPosture } = await import(eng("posture-scoring.js"));
const { computeScore } = await import(eng("scoring.js"));
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
let FAIL_NAMES = new Set();   // names answered SERVFAIL
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
  if (FAIL_NAMES.has(name)) return json({ Status: 2, Question: [{ name, type: 16 }] });
  const txt = ZONE[`${name}|${type}`];
  if (type === "TXT" && txt) {
    return json({
      Status: 0,
      Question: [{ name, type: 16 }],
      Answer: txt.map((data) => ({ name, type: 16, TTL: 300, data: quote(data) })),
    });
  }
  if (name === "example.com" || name === "mail.example.com") {
    return json({ Status: 0, Question: [{ name, type: 1 }], Answer: type === "A" ? [{ name, type: 1, TTL: 300, data: "192.0.2.10" }] : [] });
  }
  return json({ Status: 0, Question: [{ name, type: 16 }] });
};
const zone = ({ spf = null, dmarc = null, orgDmarc = null, fail = [] } = {}) => {
  ZONE = {};
  if (spf) ZONE["example.com|TXT"] = [spf];
  if (dmarc) ZONE["_dmarc.example.com|TXT"] = [dmarc];
  if (orgDmarc) ZONE["_dmarc.example.com|TXT"] = [orgDmarc];
  FAIL_NAMES = new Set(fail);
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

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
