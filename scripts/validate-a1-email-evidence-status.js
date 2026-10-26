#!/usr/bin/env node
//
// A1 — Non-DMARC Email evidence-status honesty validator.
//
// Proves SPF and DKIM probe FAILURES / non-execution do not collapse into
// "missing" / "not verified" conclusions, score penalties, or customer-facing
// negatives. Uses the REAL producers: the email-scan observation classifiers,
// computeScore, and the email-intel enrich/build functions. A failed probe →
// unavailable; an unexecuted probe → not_yet_assessed; both are score-neutral.
//
// Pure-function harness: no DNS, no D1/R2, no network. Node 24+.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENG = path.join(ROOT, "workers", "scan-api", "src", "engines");
const absUrl = (f) => pathToFileURL(path.join(ENG, f)).href;

const { dmarcObservationStatusFromDnsResult, dkimObservationStatusFromResults } = await import(absUrl("email-scan.js"));
const { isEmailProbeUnobserved, parseSpfRecord } = await import(absUrl("email-analysis.js"));
const { computeScore } = await import(absUrl("scoring.js"));
const { enrichSpf, enrichDkim, buildEmailIntelFindings, buildEmailBusinessImpacts } = await import(absUrl("email-intel.js"));

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "ok  " : "FAIL"} - ${name}${!cond && detail ? ` -- ${detail}` : ""}`);
};

const fulfilled = (status, answer = []) => ({ status: "fulfilled", value: { Status: status, Answer: answer } });
const rejected = () => ({ status: "rejected", reason: new Error("dns failure") });
const DOMAIN = "example.com";

// ── 1. Probe outcome → observation status (real classifiers) ─────────────────
ok("SPF rejected promise → unavailable", dmarcObservationStatusFromDnsResult(rejected()) === "unavailable");
ok("SPF SERVFAIL (Status 2) → unavailable", dmarcObservationStatusFromDnsResult(fulfilled(2)) === "unavailable");
ok("SPF NOERROR zero-answer → observed", dmarcObservationStatusFromDnsResult(fulfilled(0, [])) === "observed");
ok("SPF NXDOMAIN → observed", dmarcObservationStatusFromDnsResult(fulfilled(3, [])) === "observed");
ok("SPF not_executed → not_yet_assessed", dmarcObservationStatusFromDnsResult({ status: "not_executed" }) === "not_yet_assessed");
ok("DKIM all probes failed → unavailable", dkimObservationStatusFromResults([rejected(), rejected()]) === "unavailable");
ok("DKIM any probe completed → observed (non-match is observed absence)", dkimObservationStatusFromResults([fulfilled(0, []), rejected()]) === "observed");
ok("DKIM no probes run → not_yet_assessed", dkimObservationStatusFromResults([]) === "not_yet_assessed");
ok("isEmailProbeUnobserved: unavailable & not_yet_assessed only",
  isEmailProbeUnobserved("unavailable") && isEmailProbeUnobserved("not_yet_assessed") &&
  !isEmailProbeUnobserved("observed") && !isEmailProbeUnobserved(undefined));

// ── 2. SCORING: email_missing_spf gated on SPF evidence status ───────────────
function modulesFor({ spfPresent, spfEvidence = null, dropEvidence = false } = {}) {
  const rec = spfPresent ? "v=spf1 -all" : null;
  const email = {
    spf: { present: spfPresent, record: rec, record_count: spfPresent ? 1 : 0 },
    spf_detail: parseSpfRecord(rec, spfPresent ? 1 : 0),
    dkim: { present: true, selector: "s1", selectors_probed: ["s1"] },
    dmarc: { present: true, policy: "reject", record: "v=DMARC1; p=reject", record_count: 1 },
  };
  if (spfEvidence) Object.defineProperty(email, "spf_evidence_status", { value: spfEvidence, enumerable: false });
  const email_security = dropEvidence ? { ...email } : email;
  return { dns: { has_mx: true, error: null }, email_security };
}
const run = (opts) => {
  const r = computeScore(modulesFor(opts), DOMAIN);
  return { score: r.score, spfMissing: r.findings.some((f) => f.id === "email_missing_spf") };
};
const basePresent = run({ spfPresent: true });                       // baseline: SPF healthy
const spfPenalty = (opts) => basePresent.score - run(opts).score;

ok("scoring: SPF present → no email_missing_spf", !basePresent.spfMissing);
ok("scoring: SPF observed-absent → email_missing_spf (genuine missing)",
  run({ spfPresent: false, spfEvidence: "observed" }).spfMissing);
ok("scoring: SPF observed-absent penalty is the real -10",
  spfPenalty({ spfPresent: false, spfEvidence: "observed" }) === 10,
  `penalty=${spfPenalty({ spfPresent: false, spfEvidence: "observed" })}`);
// Core A1 fix: probe failure must NOT become a missing record or a penalty.
ok("scoring: SPF unavailable → NO email_missing_spf",
  !run({ spfPresent: false, spfEvidence: "unavailable" }).spfMissing);
ok("scoring: SPF unavailable → 0 penalty (score-neutral)",
  spfPenalty({ spfPresent: false, spfEvidence: "unavailable" }) === 0);
ok("scoring: SPF not_yet_assessed → NO email_missing_spf",
  !run({ spfPresent: false, spfEvidence: "not_yet_assessed" }).spfMissing);
ok("scoring: SPF not_yet_assessed → 0 penalty (score-neutral)",
  spfPenalty({ spfPresent: false, spfEvidence: "not_yet_assessed" }) === 0);
// Direct-read proof: dropping the non-enumerable evidence via spread regresses to legacy.
ok("scoring: spf_evidence_status lost through spread → unavailable regresses to missing penalty",
  run({ spfPresent: false, spfEvidence: "unavailable", dropEvidence: true }).spfMissing);

// ── 3. email-intel: enrichSpf / enrichDkim + findings + impacts (real) ───────
const dmarcOk = { status: "FULLY_PROTECTED", observation_unavailable: false };
const mtaOk = { enabled: true }, tlsOk = { enabled: true };
const intelFindingIds = (spf, dkim) => buildEmailIntelFindings(spf, dmarcOk, dkim, mtaOk, tlsOk).map((f) => f.id);
const impactTechs = (spf, dkim) => buildEmailBusinessImpacts(spf, dmarcOk, dkim, mtaOk, tlsOk).map((i) => i.technical);
const dkimVerified = enrichDkim({ dkim: { present: true, selector: "s1" } });

// SPF
const spfUnavail = enrichSpf({ spf: { present: false }, spf_evidence_status: "unavailable" });
const spfAbsent = enrichSpf({ spf: { present: false }, spf_evidence_status: "observed" });
const spfPermissive = enrichSpf({ spf: { present: true, record: "v=spf1 +all", record_count: 1 } });
ok("enrichSpf: unavailable → observation_unavailable=true", spfUnavail.observation_unavailable === true);
ok("enrichSpf: observed-absent → observation_unavailable=false", spfAbsent.observation_unavailable === false);
ok("enrichSpf: observed +all → FAIL (genuine invalid preserved)", spfPermissive.status === "FAIL");
ok("intel finding: SPF unavailable → NO email_intel_spf_missing",
  !intelFindingIds(spfUnavail, dkimVerified).includes("email_intel_spf_missing"));
ok("intel finding: SPF observed-absent → email_intel_spf_missing (genuine)",
  intelFindingIds(spfAbsent, dkimVerified).includes("email_intel_spf_missing"));
ok("intel finding: SPF observed +all → email_intel_spf_permissive (genuine invalid)",
  intelFindingIds(spfPermissive, dkimVerified).includes("email_intel_spf_permissive"));
ok("intel impact: SPF unavailable → NO 'SPF Missing' impact",
  !impactTechs(spfUnavail, dkimVerified).includes("SPF Missing"));
ok("intel impact: SPF observed-absent → 'SPF Missing' impact",
  impactTechs(spfAbsent, dkimVerified).includes("SPF Missing"));

// DKIM
const dkimUnavail = enrichDkim({ dkim: { present: false }, dkim_evidence_status: "unavailable" });
const dkimNotFound = enrichDkim({ dkim: { present: false }, dkim_evidence_status: "observed" });
ok("enrichDkim: unavailable → observation_unavailable=true", dkimUnavail.observation_unavailable === true);
ok("enrichDkim: observed-not-found → observation_unavailable=false", dkimNotFound.observation_unavailable === false);
ok("intel finding: DKIM unavailable → NO email_intel_dkim_not_found",
  !intelFindingIds(spfAbsent, dkimUnavail).includes("email_intel_dkim_not_found"));
ok("intel finding: DKIM observed-not-found → email_intel_dkim_not_found (genuine)",
  intelFindingIds(spfAbsent, dkimNotFound).includes("email_intel_dkim_not_found"));
ok("intel impact: DKIM unavailable → NO 'DKIM Not Verified' impact",
  !impactTechs(spfAbsent, dkimUnavail).includes("DKIM Not Verified"));
ok("intel impact: DKIM observed-not-found → 'DKIM Not Verified' impact",
  impactTechs(spfAbsent, dkimNotFound).includes("DKIM Not Verified"));

// ── 4. MUTATION HARNESS — the evidence gate is load-bearing ──────────────────
// Rewrite a consumer's relative imports to absolute originals, optionally swapping
// email-analysis.js for a mutant, then apply a mutation and re-run computeScore on
// the SPF-unavailable case. If the gate were removed, unavailable would regress to a
// missing finding + penalty.
const scoringSrc = fs.readFileSync(path.join(ENG, "scoring.js"), "utf8");
const analysisSrc = fs.readFileSync(path.join(ENG, "email-analysis.js"), "utf8");
const rewriteRel = (src, overrides = {}) =>
  src
    .replace(/from "\.\/([^"]+)"/g, (_m, f) => `from ${JSON.stringify(overrides[f] || absUrl(f))}`)
    // Parent-relative imports (e.g. email-analysis.js -> ../lib/serviceability.js,
    // the canonical eligibility authority) resolve to their ORIGINALS too — the
    // temp copy must consume the real canonical module, never a stub.
    .replace(/from "\.\.\/([^"]+)"/g, (_m, f) => `from ${JSON.stringify(pathToFileURL(path.join(ENG, "..", f)).href)}`);

async function scoringMutant({ scoringMutate = (s) => s, analysisMutate = null }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1-"));
  let eaOverride = {};
  if (analysisMutate) {
    const eaSrc = rewriteRel(analysisMutate(analysisSrc));
    const eaFile = path.join(dir, "email-analysis.mjs");
    fs.writeFileSync(eaFile, eaSrc);
    eaOverride = { "email-analysis.js": pathToFileURL(eaFile).href };
  }
  const scSrc = scoringMutate(rewriteRel(scoringSrc, eaOverride));
  const scFile = path.join(dir, "scoring.mjs");
  fs.writeFileSync(scFile, scSrc);
  const mod = await import(`${pathToFileURL(scFile).href}?t=${Date.now()}-${dir}`);
  const r = mod.computeScore(modulesFor({ spfPresent: false, spfEvidence: "unavailable" }), DOMAIN);
  fs.rmSync(dir, { recursive: true, force: true });
  return { spfMissing: r.findings.some((f) => f.id === "email_missing_spf"), score: r.score };
}

// M1: neuter isEmailProbeUnobserved (email-analysis) → unavailable treated as observed.
const m1Src = (s) => s.replace(
  'return status === "unavailable" || status === "not_yet_assessed";',
  "return false;");
ok("mutation anchor M1 present", m1Src(analysisSrc) !== analysisSrc);
const m1 = await scoringMutant({ analysisMutate: m1Src });
ok("M1: collapse unavailable→missing is CAUGHT (missing finding reappears)", m1.spfMissing === true);
ok("M1: penalise unavailable is CAUGHT (score drops below baseline)", m1.score < basePresent.score);

// M2: remove the SPF evidence gate in scoring directly.
const m2Src = (s) => s.replace(
  "if (!spfUnobserved && !modules.email_security?.spf?.present) {",
  "if (!modules.email_security?.spf?.present) {");
ok("mutation anchor M2 present", m2Src(scoringSrc) !== scoringSrc);
const m2 = await scoringMutant({ scoringMutate: m2Src });
ok("M2: dropping the scoring gate is CAUGHT (unavailable → missing + penalty)",
  m2.spfMissing === true && m2.score < basePresent.score);

// ── 5. Narrowed DKIM sweep: a failed root TXT lookup skips the provider selectors ──
// Real runEmailModule + the real downstream remediation, scoring and email-intel
// paths, on synthetic DoH answers (no network). The key is published only under a
// provider (phase 2) selector, which is chosen from the root SPF record.
const PROTON = "proton.example.com";
const PROTON_SPF = "v=spf1 include:_spf.protonmail.ch ~all";
const realFetch = globalThis.fetch;
let dnsFail = null, keys = { protonmail: true, google: false }, rootSpf = PROTON_SPF;
globalThis.fetch = async (input) => {
  const u = new URL(typeof input === "string" ? input : input.url);
  if (u.hostname !== "cloudflare-dns.com") throw new Error(`offline validator refused ${u.hostname}`);
  const name = u.searchParams.get("name"), type = u.searchParams.get("type");
  if (dnsFail && name === dnsFail.name && type === "TXT") {
    if (dnsFail.kind === "timeout") throw new Error("synthetic timeout");
    return new Response(JSON.stringify({ Status: 2, Answer: [] }), { status: 200 });
  }
  let answer = [];
  if (name === PROTON && type === "TXT" && rootSpf) answer = [{ type: 16, data: `"${rootSpf}"` }];
  for (const sel of ["protonmail", "google"]) {
    if (name === `${sel}._domainkey.${PROTON}` && type === "TXT" && keys[sel]) answer = [{ type: 16, data: '"v=DKIM1; k=rsa; p=MIIB"' }];
  }
  return new Response(JSON.stringify({ Status: answer.length ? 0 : 3, Answer: answer }), { status: 200 });
};
const { runEmailModule } = await import(absUrl("email-scan.js"));
const { runEmailIntelModule } = await import(absUrl("email-intel.js"));
async function emailScan({ failing = null, published = { protonmail: true, google: false }, spf = PROTON_SPF, scanModule = runEmailModule } = {}) {
  dnsFail = failing; keys = published; rootSpf = spf;
  const email = await scanModule(PROTON, { dmarcOwnedByCore: true });
  const dns = { has_mx: true, error: null, mx_records: [] };
  const intel = await runEmailIntelModule(PROTON, email, dns, { fetcher: async () => { throw new Error("offline"); } });
  const score = computeScore({ dns, email_security: email, email_intel: intel }, PROTON);
  return {
    present: email.dkim.present,
    status: email.dkim_evidence_status,
    spfStatus: email.spf_evidence_status,
    action: (email.remediation_actions || []).some((a) => a.id === "dkim_verification_uncertain"),
    finding: score.findings.some((f) => f.id === "email_dkim_not_detected"),
    spfMissing: score.findings.some((f) => f.id === "email_missing_spf"),
    intelFinding: (intel.findings || []).some((f) => f.id === "email_intel_dkim_not_found"),
    intelUnavailable: intel.dkim?.observation_unavailable === true,
    intelStatus: intel.dkim?.status ?? null,
    probed: email.dkim.selectors_probed,
    answered: email.dkim.selectors_answered ?? [],
  };
}
const rootTimeout = { name: PROTON, kind: "timeout" };
const narrowed = await emailScan({ failing: rootTimeout });
const narrowedServfail = await emailScan({ failing: { name: PROTON, kind: "servfail" } });
const includeOnly = await emailScan({ failing: { name: "_spf.protonmail.ch", kind: "timeout" } });
const genuineNoKey = await emailScan({ published: { protonmail: false, google: false } });
const noSpfNoKey = await emailScan({ published: { protonmail: false, google: false }, spf: null });
const phase1RootFail = await emailScan({ failing: rootTimeout, published: { protonmail: false, google: true } });
const full = await emailScan();
ok("narrowed sweep (root TXT timeout): no key is UNAVAILABLE, not observed absence", narrowed.present === false && narrowed.status === "unavailable");
ok("narrowed sweep (root TXT SERVFAIL): UNAVAILABLE", narrowedServfail.status === "unavailable");
ok("narrowed sweep: no 'Confirm the active DKIM selector' remediation", !narrowed.action);
ok("narrowed sweep: no email_dkim_not_detected scoring finding", !narrowed.finding);
ok("narrowed sweep: no email_intel_dkim_not_found finding", !narrowed.intelFinding);
ok("narrowed sweep: email intel keeps the unknown explicit (NOT_VERIFIED, observation_unavailable)",
  narrowed.intelStatus === "NOT_VERIFIED" && narrowed.intelUnavailable);
ok("narrowed sweep: unrelated SPF behaviour unchanged (unavailable SPF is not missing)",
  narrowed.spfStatus === "unavailable" && !narrowed.spfMissing);
ok("full sweep: provider-only key found and observed", full.present === true && full.status === "observed");
ok("SPF include failure does not narrow: key found, observed", includeOnly.present === true && includeOnly.status === "observed");
ok("phase-1 key under a failed root TXT lookup: still found and observed", phase1RootFail.present === true && phase1RootFail.status === "observed");
ok("genuine no-key with full coverage: observed, with action and findings",
  genuineNoKey.present === false && genuineNoKey.status === "observed" && genuineNoKey.action && genuineNoKey.finding && genuineNoKey.intelFinding);
ok("observed domain without SPF and without key: observed no-key (nothing to narrow)",
  noSpfNoKey.present === false && noSpfNoKey.status === "observed" && noSpfNoKey.finding);

// Conclusive-answer coverage: a selector that was asked but timed out / SERVFAILed
// is probed, never answered; only NOERROR/NXDOMAIN answers count.
const providerTimeout = await emailScan({ failing: { name: `protonmail._domainkey.${PROTON}`, kind: "timeout" } });
const providerServfail = await emailScan({ failing: { name: `protonmail._domainkey.${PROTON}`, kind: "servfail" } });
ok("full sweep: the decisive provider selector answered", full.answered.includes("protonmail"));
ok("provider selector timeout: probed but NOT answered",
  providerTimeout.probed.includes("protonmail") && !providerTimeout.answered.includes("protonmail"));
ok("provider selector SERVFAIL: probed but NOT answered",
  providerServfail.probed.includes("protonmail") && !providerServfail.answered.includes("protonmail"));
ok("genuine no-key sweep: the provider selector answered (NXDOMAIN is conclusive)", genuineNoKey.answered.includes("protonmail"));
ok("narrowed sweep: the provider selector is neither probed nor answered",
  !narrowed.probed.includes("protonmail") && !narrowed.answered.includes("protonmail"));

// M4: count every attempted selector as answered -> a timed-out selector is
// reported as conclusive coverage again.
{
  const m4Src = (src) => src.replace(
    "selectors.filter((_, i) => dmarcObservationStatusFromDnsResult(results[i]) === DMARC_OBSERVATION_STATUS.OBSERVED);",
    "selectors.filter(() => true);");
  const src = fs.readFileSync(path.join(ENG, "email-scan.js"), "utf8");
  ok("mutation anchor M4 present", m4Src(src) !== src);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1-m4-"));
  const file = path.join(dir, "email-scan.mjs");
  fs.writeFileSync(file, rewriteRel(m4Src(src)));
  const mutant = await import(`${pathToFileURL(file).href}?t=${Date.now()}`);
  const m4 = await emailScan({ failing: { name: `protonmail._domainkey.${PROTON}`, kind: "timeout" }, scanModule: mutant.runEmailModule });
  fs.rmSync(dir, { recursive: true, force: true });
  ok("M4: counting attempted selectors as answered is CAUGHT", m4.answered.includes("protonmail"));
}

// M3: remove the narrowing guard in email-scan -> the narrowed sweep is published
// as an observed absence again (action + findings reappear).
const emailScanSrc = fs.readFileSync(path.join(ENG, "email-scan.js"), "utf8");
const m3Src = (src) => src.replace(
  "const dkimSweepNarrowed = !dkimSelector && spfObservationStatus !== DMARC_OBSERVATION_STATUS.OBSERVED;",
  "const dkimSweepNarrowed = false;");
ok("mutation anchor M3 present", m3Src(emailScanSrc) !== emailScanSrc);
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1-m3-"));
  const file = path.join(dir, "email-scan.mjs");
  fs.writeFileSync(file, rewriteRel(m3Src(emailScanSrc)));
  const mutant = await import(`${pathToFileURL(file).href}?t=${Date.now()}`);
  const m3 = await emailScan({ failing: rootTimeout, scanModule: mutant.runEmailModule });
  fs.rmSync(dir, { recursive: true, force: true });
  ok("M3: dropping the narrowing guard is CAUGHT (observed absence + finding reappear)",
    m3.status === "observed" && m3.finding === true && m3.action === true);
}
globalThis.fetch = realFetch;

console.log(`\nA1 email evidence-status: ${pass}/${pass + fail} passed`);
if (fail) { console.error("a1-email-evidence-status validation FAILED"); process.exit(1); }
console.log("a1-email-evidence-status validation passed");
