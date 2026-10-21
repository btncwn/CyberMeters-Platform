#!/usr/bin/env node
//
// ADR-003 backend consumer-switch validator.
//
// Proves the backend TRUTH consumers (scoring, external security check, Business Risk, and the
// email-intel status/finding) consume the canonical dmarc_state produced by
// deriveDmarcState() — read DIRECTLY off the live email module result — instead of
// re-deriving enforcement from raw p / pct / sp / present / valid.
//
// Uses the REAL producers (computeScore, resolveSecurityCheckDomainStates,
// deriveScanBusinessRisk, enrichEmailIntel via runEmailIntel is DNS-bound, so the
// intel status is validated through its shared mapping). No copied constants stand
// in for producer output. dmarc_state is attached NON-ENUMERABLE exactly as
// email-scan.js does, so the "lost through spread" proof is faithful.
//
// Pure-function harness: no DNS, no D1/R2, no network. Node 24+.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENG = path.join(ROOT, "workers", "scan-api", "src", "engines");
const p = (f) => path.join(ENG, f);

const { computeScore } = await import(pathToFileURL(p("scoring.js")).href);
const { resolveSecurityCheckDomainStates } = await import(pathToFileURL(p("security-check-domains.js")).href);
const { deriveScanBusinessRisk } = await import(pathToFileURL(p("business-risk.js")).href);
const { deriveDmarcState } = await import(pathToFileURL(p("dmarc-state.js")).href);
const { parseDmarcRecord } = await import(pathToFileURL(p("email-analysis.js")).href);
const { DMARC_MOT_CONTRIBUTION, DMARC_INTEL_STATUS, assertConsumerMappingsComplete } =
  await import(pathToFileURL(p("dmarc-canonical-consumers.js")).href);

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "ok  " : "FAIL"} - ${name}${!cond && detail ? ` -- ${detail}` : ""}`);
};

const DOMAIN = "example.com";
const OBS = "2026-07-18T12:00:00.000Z";

// Build a canonical dmarc_state from a record string + observation status.
function stateFor({ record = null, recordCount, evidence_status = "observed", assessed } = {}) {
  const detail = parseDmarcRecord(record, recordCount ?? (record ? 1 : 0));
  const input = { dmarc: detail, policy_source: "observed_dns", last_observed: OBS };
  if (assessed === false) input.assessed = false;
  else input.evidence_status = evidence_status;
  return { detail, state: deriveDmarcState(input) };
}

// Build a `modules` object whose email_security carries a NON-ENUMERABLE dmarc_state,
// exactly like runEmailModule. SPF/DKIM are healthy so the only material email finding
// is the DMARC one. `dropState` spreads email_security (drops the non-enum property).
function buildModules(scn, { dropState = false } = {}) {
  const email = {
    dmarc: {
      present: !!scn.detail.raw,
      policy: scn.detail.policy,
      record: scn.detail.raw,
      record_count: scn.detail.record_count,
    },
    dmarc_detail: scn.detail,
    spf: { present: true, record: "v=spf1 -all" },
    dkim: { present: true, status: "VERIFIED" },
  };
  Object.defineProperty(email, "dmarc_state", { value: scn.state, enumerable: false });
  const email_security = dropState ? { ...email } : email;
  return { dns: { has_mx: true, error: null }, email_security };
}

function reportFor(modules, findings) {
  return {
    modules,
    findings,
    scan_quality: { status: "complete", modules_skipped: [] },
    completed_at: OBS,
    scan_id: "scan_test",
  };
}

function emailFindingIds(findings) {
  return findings.filter((f) => /^email_/.test(f.id)).map((f) => f.id);
}
function motEmailState(report) {
  const domains = resolveSecurityCheckDomainStates(report);
  return domains.find((d) => d.domain_key === "email_protection")?.state;
}

// ── Canonical scenarios ──────────────────────────────────────────────────────
const S = {
  reject_enforced:     stateFor({ record: "v=DMARC1; p=reject; rua=mailto:d@example.com" }),
  quarantine_enforced: stateFor({ record: "v=DMARC1; p=quarantine; rua=mailto:d@example.com" }),
  partial_reject:      stateFor({ record: "v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com" }),
  monitoring:          stateFor({ record: "v=DMARC1; p=none; rua=mailto:d@example.com" }),
  invalid_record:      stateFor({ record: "v=DMARC1; p=future" }),
  no_record:           stateFor({ record: null, evidence_status: "observed" }),
  not_observed:        stateFor({ record: null, evidence_status: "unavailable" }),
  not_yet_assessed:    stateFor({ assessed: false }),
};
// Sanity: every scenario resolved to the intended enforcement_level via the REAL model.
for (const [k, v] of Object.entries(S)) {
  ok(`scenario ${k} → enforcement_level ${k}`, v.state.enforcement_level === k,
    `got ${v.state.enforcement_level}`);
}

// ── 1. SCORING: canonical findings + score neutrality ────────────────────────
function scoreRun(scn, opts) {
  const modules = buildModules(scn, opts);
  const r = computeScore(modules, DOMAIN);
  return { score: r.score, findings: r.findings, ids: emailFindingIds(r.findings) };
}
const runReject = scoreRun(S.reject_enforced);         // baseline: no DMARC penalty
const baseline = runReject.score;
const dmarcPenalty = (scn) => baseline - scoreRun(scn).score;

ok("scoring: reject_enforced emits no DMARC finding",
  !runReject.ids.includes("email_missing_dmarc") && !runReject.ids.includes("email_dmarc_policy_none"));
ok("scoring: no_record emits email_missing_dmarc",
  scoreRun(S.no_record).ids.includes("email_missing_dmarc"));
ok("scoring: monitoring emits email_dmarc_policy_none",
  scoreRun(S.monitoring).ids.includes("email_dmarc_policy_none"));

// The core honesty fix: UNAVAILABLE must never take the missing-DMARC penalty.
const notObservedRun = scoreRun(S.not_observed);
ok("scoring: not_observed emits NO email_missing_dmarc (unavailable ≠ missing)",
  !notObservedRun.ids.includes("email_missing_dmarc"));
ok("scoring: not_observed DMARC penalty is exactly 0 (score-neutral)",
  dmarcPenalty(S.not_observed) === 0, `penalty=${dmarcPenalty(S.not_observed)}`);
ok("scoring: not_yet_assessed DMARC penalty is exactly 0 (score-neutral)",
  dmarcPenalty(S.not_yet_assessed) === 0, `penalty=${dmarcPenalty(S.not_yet_assessed)}`);

// Monotonicity across the levels scoring expresses (weaker ≤ stronger score).
const pNoRecord = dmarcPenalty(S.no_record);
const pMonitoring = dmarcPenalty(S.monitoring);
const pReject = dmarcPenalty(S.reject_enforced);
ok("scoring: penalty monotonic no_record ≥ monitoring ≥ reject_enforced",
  pNoRecord >= pMonitoring && pMonitoring >= pReject && pReject === 0,
  `no_record=${pNoRecord} monitoring=${pMonitoring} reject=${pReject}`);
ok("scoring: no_record strictly penalised more than monitoring",
  pNoRecord > pMonitoring, `${pNoRecord} vs ${pMonitoring}`);

// PROOF the consumer follows dmarc_state, not raw: not_observed has raw dmarc.present=false
// (looks missing) yet takes NO missing penalty. A raw re-derivation would penalise it.
ok("scoring: follows dmarc_state not raw (raw present=false + not_observed → no penalty)",
  buildModules(S.not_observed).email_security.dmarc.present === false &&
  dmarcPenalty(S.not_observed) === 0);

// PROOF dmarc_state must be read directly: if it is dropped by a spread, not_observed
// silently regresses to the legacy missing penalty.
const spreadRun = scoreRun(S.not_observed, { dropState: true });
ok("scoring: dmarc_state lost through spread → regresses to missing penalty (direct read required)",
  spreadRun.ids.includes("email_missing_dmarc"));

// ── 2. Domain state: full nine-rung mapping (ADR-003 §7) ────────────────────────
function motFor(scn, opts) {
  const modules = buildModules(scn, opts);
  const findings = computeScore(modules, DOMAIN).findings; // real findings feed the resolver
  return motEmailState(reportFor(modules, findings));
}
const MOT_EXPECT = {
  reject_enforced: "assessed_healthy",
  quarantine_enforced: "issue_detected",
  partial_reject: "issue_detected",
  invalid_record: "issue_detected",
  monitoring: "issue_detected",
  no_record: "issue_detected",
  not_observed: "evidence_insufficient",
};
for (const [level, expected] of Object.entries(MOT_EXPECT)) {
  ok(`domain-state: ${level} → ${expected}`, motFor(S[level]) === expected, `got ${motFor(S[level])}`);
}
// Explicit collapse guards from the task list:
ok("domain-state: quarantine_enforced is NOT assessed_healthy (quarantine ≠ reject)",
  motFor(S.quarantine_enforced) !== "assessed_healthy");
ok("domain-state: reject_enforced is NOT issue_detected",
  motFor(S.reject_enforced) !== "issue_detected");
ok("domain-state: partial_reject is NOT assessed_healthy (partial ≠ full)",
  motFor(S.partial_reject) !== "assessed_healthy");
ok("domain-state: invalid_record is NOT assessed_healthy (invalid ≠ healthy credit)",
  motFor(S.invalid_record) !== "assessed_healthy");
// dmarc_state dropped by spread → the resolver cannot see the DMARC verdict and a
// reject_enforced domain still resolves healthy off SPF/DKIM (legacy), while a
// not_observed domain would wrongly read healthy — proving the direct read matters.
ok("domain-state: dmarc_state lost through spread → not_observed no longer evidence_insufficient",
  motFor(S.not_observed, { dropState: true }) !== "evidence_insufficient");

// ── 3. BUSINESS RISK: finding-driven, canonical transitively ─────────────────
// BR is a pure function of finding IDs (weak_email_security keys on
// email_missing_dmarc / email_dmarc_policy_none). Prove the canonical scoring switch
// removes the false weak-email signal for not_observed and keeps it for no_record.
function brWeakEmail(scn) {
  const modules = buildModules(scn);
  const report = reportFor(modules, computeScore(modules, DOMAIN).findings);
  const br = deriveScanBusinessRisk(report); // must run without throwing
  const ids = new Set(report.findings.map((f) => f.id));
  return { br, hasMissing: ids.has("email_missing_dmarc") || ids.has("email_dmarc_policy_none") };
}
ok("business-risk: not_observed carries NO missing/none DMARC finding (no false weak-email)",
  brWeakEmail(S.not_observed).hasMissing === false);
ok("business-risk: no_record DOES carry email_missing_dmarc (still penalised honestly)",
  brWeakEmail(S.no_record).hasMissing === true);
ok("business-risk: deriveScanBusinessRisk runs on canonical report", !!brWeakEmail(S.not_observed).br);

// ── 4. email-intel status mapping (shared source, ADR-003 §7/§11) ────────────
ok("email-intel: reject_enforced → FULLY_PROTECTED", DMARC_INTEL_STATUS.reject_enforced === "FULLY_PROTECTED");
ok("email-intel: quarantine_enforced → PARTIAL_PROTECTED (not full)", DMARC_INTEL_STATUS.quarantine_enforced === "PARTIAL_PROTECTED");
ok("email-intel: monitoring → REPORTING_ONLY", DMARC_INTEL_STATUS.monitoring === "REPORTING_ONLY");
ok("email-intel: invalid_record → ERROR (not healthy)", DMARC_INTEL_STATUS.invalid_record === "ERROR");

// ── 5. Evidence honesty: customer_asserted ≠ externally verified ─────────────
// The scan path is always observed_dns; this defensive guard proves a customer-asserted
// canonical state is NOT elevated to high-confidence external verification (PR-1 §5).
const asserted = deriveDmarcState({
  dmarc: parseDmarcRecord("v=DMARC1; p=reject; rua=mailto:d@example.com", 1),
  policy_source: "customer_asserted", last_observed: OBS,
});
ok("evidence: customer_asserted reject is low confidence (not externally verified)",
  asserted.confidence === "low" && asserted.policy_source === "customer_asserted");

// ── 6. Mapping completeness ──────────────────────────────────────────────────
ok("every canonical enforcement level has a consumer mapping", assertConsumerMappingsComplete().length === 0,
  assertConsumerMappingsComplete().join(","));

// ── 7. MUTATION HARNESS — external security check mappings are load-bearing ────────────────
// security-check-domains.js imports ONLY dmarc-canonical-consumers.js, so a mutant map
// wired into a mutant resolver proves each §7 mapping actually drives the verdict.
const mapSrc = fs.readFileSync(p("dmarc-canonical-consumers.js"), "utf8");
const motSrc = fs.readFileSync(p("security-check-domains.js"), "utf8");
const stateUrl = pathToFileURL(p("dmarc-state.js")).href;
const monitoringUrl = pathToFileURL(p("signal-monitoring-state.js")).href;
const cookieObservationUrl = pathToFileURL(p("cookie-observation.js")).href;
const tlsEvidenceUrl = pathToFileURL(p("tls-evidence.js")).href;
const identityEvidenceUrl = pathToFileURL(p("identity-evidence-contract.js")).href;
const findingsUrl = pathToFileURL(p("findings.js")).href;

function replaceExactImport(source, anchor, replacement, label) {
  const anchorCount = source.split(anchor).length - 1;
  if (anchorCount !== 1) {
    throw new Error(`HARNESS_PRECONDITION ${label} import anchor count=${anchorCount}; expected=1`);
  }
  return source.replace(anchor, replacement);
}

const findingsImportAnchor = 'from "./findings.js"';
const findingsImportReplacement = `from ${JSON.stringify(findingsUrl)}`;
for (const [name, source, expectedCount] of [
  ["missing findings import", motSrc.replace(findingsImportAnchor, ""), 0],
  ["duplicate findings import", `${motSrc}\nimport ${findingsImportAnchor};`, 2],
]) {
  let reason = "";
  try {
    replaceExactImport(source, findingsImportAnchor, findingsImportReplacement, "findings.js");
  } catch (error) {
    reason = String(error?.message || error);
  }
  ok(`mutation harness: ${name} is rejected by exact-anchor preflight`,
    reason === `HARNESS_PRECONDITION findings.js import anchor count=${expectedCount}; expected=1`,
    `reason=${reason || "none"}`);
}

async function motFromMutantMap(mutateMap, scn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-cs-"));
  try {
    const mMap = mutateMap(mapSrc).replace('from "./dmarc-state.js"', `from ${JSON.stringify(stateUrl)}`);
    const mapFile = path.join(dir, "map.mjs");
    fs.writeFileSync(mapFile, mMap);
    const mMot = motSrc
      .replace('from "./dmarc-canonical-consumers.js"', `from ${JSON.stringify(pathToFileURL(mapFile).href)}`)
      .replace('from "./signal-monitoring-state.js"', `from ${JSON.stringify(monitoringUrl)}`)
      .replace('from "./cookie-observation.js"', `from ${JSON.stringify(cookieObservationUrl)}`)
      .replace('from "./tls-evidence.js"', `from ${JSON.stringify(tlsEvidenceUrl)}`)
      .replace('from "./identity-evidence-contract.js"', `from ${JSON.stringify(identityEvidenceUrl)}`);
    const portableMot = replaceExactImport(
      mMot,
      findingsImportAnchor,
      findingsImportReplacement,
      "findings.js",
    );
    const motFile = path.join(dir, "security-check.mjs");
    fs.writeFileSync(motFile, portableMot);
    const mod = await import(`${pathToFileURL(motFile).href}?t=${OBS}`);
    const modules = buildModules(scn);
    const report = reportFor(modules, computeScore(modules, DOMAIN).findings);
    return mod.resolveSecurityCheckDomainStates(report).find((d) => d.domain_key === "email_protection")?.state;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const MUTATIONS = [
  { name: "quarantine_enforced→assessed_healthy is CAUGHT", scn: "quarantine_enforced",
    mutate: (s) => s.replace('quarantine_enforced: "issue_detected"', 'quarantine_enforced: "assessed_healthy"'),
    canon: "issue_detected" },
  { name: "reject_enforced→issue_detected is CAUGHT", scn: "reject_enforced",
    mutate: (s) => s.replace('reject_enforced:     "assessed_healthy"', 'reject_enforced:     "issue_detected"'),
    canon: "assessed_healthy" },
  { name: "invalid_record→assessed_healthy is CAUGHT", scn: "invalid_record",
    mutate: (s) => s.replace('invalid_record:      "issue_detected"', 'invalid_record:      "assessed_healthy"'),
    canon: "issue_detected" },
  { name: "not_observed→skip (would read healthy) is CAUGHT", scn: "not_observed",
    mutate: (s) => s.replace('not_observed:        "evidence_insufficient"', 'not_observed:        "skip"'),
    canon: "evidence_insufficient" },
];
for (const m of MUTATIONS) {
  const anchored = m.mutate(mapSrc) !== mapSrc;
  const mutated = anchored ? await motFromMutantMap(m.mutate, S[m.scn]) : "ANCHOR_MISSING";
  ok(`mutation ${m.name}`, anchored && mutated !== m.canon, `canon=${m.canon} mutated=${mutated}`);
}

// ── 6. Testing mode (t=y), RFC 9989 section 4.7 ──────────────────────────────
// p=reject; t=y asks receivers to quarantine and p=quarantine; t=y asks for no
// action. Every consumer grades and words the effective policy, never the bare
// p= (21 Oct 2026: a live report showed "Reject" for p=reject; t=y).
{
  const { buildDmarcPolicyJourney } = await import(pathToFileURL(p("email-analysis.js")).href);
  const { buildFreeScanObserved } = await import(pathToFileURL(p("free-scan-observed.js")).href);
  const T = {
    reject_testing:     stateFor({ record: "v=DMARC1; p=reject; t=y; rua=mailto:d@example.com" }),
    quarantine_testing: stateFor({ record: "v=DMARC1; p=quarantine; t=y; rua=mailto:d@example.com" }),
    reject_t_n:         stateFor({ record: "v=DMARC1; p=reject; t=n; rua=mailto:d@example.com" }),
  };
  ok("t=y: p=reject grades quarantine_enforced, never reject_enforced",
    T.reject_testing.state.enforcement_level === "quarantine_enforced", T.reject_testing.state.enforcement_level);
  ok("t=y: p=quarantine grades monitoring", T.quarantine_testing.state.enforcement_level === "monitoring",
    T.quarantine_testing.state.enforcement_level);
  ok("t=n leaves p=reject at reject_enforced", T.reject_t_n.state.enforcement_level === "reject_enforced",
    T.reject_t_n.state.enforcement_level);
  ok("t=y: p=reject email-intel status is not FULLY_PROTECTED",
    DMARC_INTEL_STATUS[T.reject_testing.state.enforcement_level] !== "FULLY_PROTECTED");
  ok("t=y: p=reject security-check email state equals plain p=quarantine",
    motFor(T.reject_testing) === motFor(S.quarantine_enforced), `${motFor(T.reject_testing)} vs ${motFor(S.quarantine_enforced)}`);
  const rj = buildDmarcPolicyJourney(T.reject_testing.detail);
  ok("t=y: p=reject journey is partial_enforcement (Quarantine requested), not full_enforcement",
    rj.stage === "partial_enforcement" && /t=y/.test(rj.label), JSON.stringify(rj));
  const qj = buildDmarcPolicyJourney(T.quarantine_testing.detail);
  ok("t=y: p=quarantine journey is monitoring", qj.stage === "monitoring" && /t=y/.test(qj.label), JSON.stringify(qj));
  ok("plain p=reject journey is still full_enforcement", buildDmarcPolicyJourney(S.reject_enforced.detail).stage === "full_enforcement");
  const q = scoreRun(T.quarantine_testing);
  const none = q.findings.find((f) => f.id === "email_dmarc_policy_none");
  ok("t=y: p=quarantine raises the monitor-only finding", Boolean(none), q.ids.join(","));
  ok("t=y: the monitor-only finding states the declared p=quarantine and t=y, never p=none",
    Boolean(none) && /p=quarantine in testing mode \(t=y\)/.test(none.description) && !/\(p=none\)/.test(none.title),
    `${none?.title} | ${none?.description}`);
  ok("t=y: p=reject scores exactly like plain p=quarantine",
    scoreRun(T.reject_testing).score === scoreRun(S.quarantine_enforced).score);
  const observed = (scn) => {
    const modules = buildModules(scn);
    return buildFreeScanObserved(modules, new Map([["email_security", "completed"]]))
      .email_protection.find((o) => o.id === "dmarc_enforcing_policy")?.text;
  };
  ok("t=y: observed line states the declared p=reject and the effective quarantine",
    observed(T.reject_testing) === "DMARC policy p=reject observed in testing mode (t=y), so receivers are asked to quarantine",
    observed(T.reject_testing));
  ok("t=y: p=quarantine prints no enforcing-policy line", observed(T.quarantine_testing) === undefined, observed(T.quarantine_testing));
  ok("plain p=reject observed line is unchanged", observed(S.reject_enforced) === "DMARC policy p=reject observed", observed(S.reject_enforced));

  // Mutants: each puts back the "bare p=" reading and must be caught.
  const absolutise = (source, file) => source.replace(/from "(\.\.?\/[^"]+)"/g,
    (_, rel) => `from ${JSON.stringify(pathToFileURL(path.resolve(path.dirname(file), rel)).href)}`);
  async function mutantModule(file, before, after) {
    const source = fs.readFileSync(file, "utf8");
    if (source.split(before).length !== 2) return null;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-t-"));
    try {
      const out = path.join(dir, path.basename(file).replace(/\.js$/, ".mjs"));
      fs.writeFileSync(out, absolutise(source.replace(before, after), file));
      return await import(pathToFileURL(out).href);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  }
  const stateMutant = await mutantModule(p("dmarc-state.js"),
    'const testing = String(parsed?.tags?.t ?? "").trim().toLowerCase() === "y";', "const testing = false;");
  ok("mutation dmarc-state ignores t=y is CAUGHT (would grade reject_enforced)",
    stateMutant != null && stateMutant.deriveDmarcState({ dmarc: T.reject_testing.detail, policy_source: "observed_dns",
      evidence_status: "observed", last_observed: OBS }).enforcement_level !== "quarantine_enforced");
  const journeyMutant = await mutantModule(p("email-analysis.js"),
    'return String(detail?.tags?.t ?? "").trim().toLowerCase() === "y";', "return false;");
  ok("mutation journey ignores t=y is CAUGHT (would read full_enforcement)",
    journeyMutant != null && journeyMutant.buildDmarcPolicyJourney(T.reject_testing.detail).stage === "full_enforcement");
}

console.log(`\nDMARC consumer switch: ${pass}/${pass + fail} passed`);
if (fail) { console.error("dmarc-consumer-switch validation FAILED"); process.exit(1); }
console.log("dmarc-consumer-switch validation passed");
