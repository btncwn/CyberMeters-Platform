#!/usr/bin/env node
//
// B — Workspace Scorecard Canonicalisation validator.
//
// Proves the live scorecard's per-domain wording (Brand, Certificates, Shadow-IT,
// Attack-Surface admin) derives from canonical Cyber MOT state / A3 admin
// evidence_status — never from raw counts / null-defaults — so unavailable /
// not_assessed evidence can never render "none detected" / "looks normal" / healthy.
// Uses the REAL buildScorecardSections and the REAL scorecard-domain-state helper.
//
// Pure-function harness: no live D1/R2. Node 24+.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENG = path.join(ROOT, "workers", "scan-api", "src", "engines");
const absU = (f) => pathToFileURL(path.join(ENG, f)).href;
const SCORECARD = path.join(ENG, "scorecard.js");
const HELPER = path.join(ENG, "scorecard-domain-state.js");

const { buildScorecardSections } = await import(pathToFileURL(SCORECARD).href);
const { scorecardBehaviour, canSayHealthy } = await import(pathToFileURL(HELPER).href);

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "ok  " : "FAIL"} - ${name}${!cond && detail ? ` -- ${detail}` : ""}`);
};
const REASSURING = /none|no exposed|no third-party|no external|looks normal|no active|not resolving|none currently|none detected|no exposed login/i;

// ── 0. Shared helper mapping (real) ──────────────────────────────────────────
ok("helper: assessed_healthy → healthy", scorecardBehaviour("assessed_healthy") === "healthy");
ok("helper: issue_detected → issue", scorecardBehaviour("issue_detected") === "issue");
ok("helper: evidence_insufficient → unavailable", scorecardBehaviour("evidence_insufficient") === "unavailable");
ok("helper: not_yet_assessed → not_assessed", scorecardBehaviour("not_yet_assessed") === "not_assessed");
ok("helper: monitoring_only → not_assessed", scorecardBehaviour("monitoring_only") === "not_assessed");
ok("helper: null/unknown → not_assessed", scorecardBehaviour(null) === "not_assessed");
ok("helper: canSayHealthy only for assessed_healthy",
  canSayHealthy("assessed_healthy") && !canSayHealthy("evidence_insufficient") && !canSayHealthy(null) && !canSayHealthy("monitoring_only"));

// ── scorecard payload builder + section lookup ───────────────────────────────
function scorecardWith(o = {}) {
  return {
    cyber_mot_domains: o.cmd || [],
    admin_surface_evidence_status: o.adminEv ?? null,
    admin_surfaces: o.admin_surfaces ?? 0,
    brand_risks: o.brand ?? { total: 5, active: 0, high: 0, medium: 0, low: 0 },
    certificate_risks: o.cert ?? { risk_level: null, signals: 0, days_until_expiry: null },
    third_party_assets: o.tpa ?? 0,
    saas_exposures: o.saas ?? 0,
    active_assets: 3, new_assets_30d: 0, asset_events_30d: 0,
    vendors_detected: 0, vendor_risk: { high: 0, medium: 0, low: 0 },
    critical_findings: 0, high_findings: 0, medium_findings: 0, low_findings: 0,
  };
}
const cmd = (key, state) => [{ domain_key: key, state }];
const sec = (payload, title, mod = buildScorecardSections) => mod(payload).find((s) => s.title === title);

// ── 1. BRAND — gated on brand_protection ─────────────────────────────────────
{
  const healthy = sec(scorecardWith({ cmd: cmd("brand_protection", "assessed_healthy") }), "Brand Monitoring");
  ok("brand: assessed_healthy + zero active → positive summary + ok", healthy.status === "ok" && /none currently resolving/i.test(healthy.summary));
  const unavail = sec(scorecardWith({ cmd: cmd("brand_protection", "evidence_insufficient") }), "Brand Monitoring");
  ok("brand: unavailable + zero active → NEUTRAL (no 'none resolving'), status unknown",
    unavail.status === "unknown" && !REASSURING.test(unavail.summary) && /could not be assessed/i.test(unavail.summary));
  const notAssessed = sec(scorecardWith({ cmd: cmd("brand_protection", "not_yet_assessed") }), "Brand Monitoring");
  ok("brand: not_assessed → NEUTRAL 'not been assessed', status unknown", notAssessed.status === "unknown" && /not been assessed yet/i.test(notAssessed.summary));
  const issue = sec(scorecardWith({ cmd: cmd("brand_protection", "issue_detected"), brand: { total: 3, active: 2, high: 1, medium: 0, low: 0 } }), "Brand Monitoring");
  ok("brand: active>0 → issue surfaces (critical/warning), never softened", issue.status === "critical" || issue.status === "warning");
  // canonical issue with ZERO raw active count still surfaces (finding never hidden by count).
  const issueZeroCount = sec(scorecardWith({ cmd: cmd("brand_protection", "issue_detected") }), "Brand Monitoring");
  ok("brand: issue_detected with zero raw count still NOT healthy (issue not hidden by count)", issueZeroCount.status !== "ok");
}

// ── 2. CERTIFICATES — gated on certificates_trust ────────────────────────────
{
  const healthy = sec(scorecardWith({ cmd: cmd("certificates_trust", "assessed_healthy") }), "Certificate Intelligence");
  ok("cert: assessed_healthy → 'looks normal' + ok", healthy.status === "ok" && /looks normal/i.test(healthy.summary));
  const nullState = sec(scorecardWith({ cmd: [] /* no certificates_trust state */, cert: { risk_level: null, signals: 0 } }), "Certificate Intelligence");
  ok("cert: null state + null risk → NEUTRAL, NOT 'looks normal'", nullState.status === "unknown" && !/looks normal/i.test(nullState.summary));
  const unavail = sec(scorecardWith({ cmd: cmd("certificates_trust", "evidence_insufficient") }), "Certificate Intelligence");
  ok("cert: unavailable → 'could not be assessed', not 'looks normal'", /could not be assessed/i.test(unavail.summary) && !/looks normal/i.test(unavail.summary));
  const issue = sec(scorecardWith({ cert: { risk_level: "critical", signals: 2 } }), "Certificate Intelligence");
  ok("cert: real risk signals → issue surfaces", issue.status === "critical" || issue.status === "warning");
}

// ── 3. SHADOW IT — Third-Party / SaaS gated on shadow_it_unmanaged_technology ─
{
  const healthy = sec(scorecardWith({ cmd: cmd("shadow_it_unmanaged_technology", "assessed_healthy") }), "Third-Party Assets");
  ok("shadow: assessed_healthy + zero → 'none detected' + ok", healthy.status === "ok" && /no third-party/i.test(healthy.summary));
  const monitoring = sec(scorecardWith({ cmd: cmd("shadow_it_unmanaged_technology", "monitoring_only") }), "Third-Party Assets");
  ok("shadow: monitoring_only + zero → NEUTRAL, NOT 'none detected'", monitoring.status === "unknown" && !REASSURING.test(monitoring.summary));
  const saasHealthy = sec(scorecardWith({ cmd: cmd("shadow_it_unmanaged_technology", "assessed_healthy") }), "SaaS Exposure");
  ok("shadow SaaS: assessed_healthy + zero → 'none detected' + ok", saasHealthy.status === "ok" && /no externally exposed/i.test(saasHealthy.summary));
  const saasMon = sec(scorecardWith({ cmd: cmd("shadow_it_unmanaged_technology", "not_yet_assessed") }), "SaaS Exposure");
  ok("shadow SaaS: not_assessed + zero → NEUTRAL", saasMon.status === "unknown" && !REASSURING.test(saasMon.summary));
  const tpaIssue = sec(scorecardWith({ tpa: 4 }), "Third-Party Assets");
  ok("shadow: real count>0 → issue surfaces", tpaIssue.status === "warning");
}

// ── 4. ATTACK SURFACE admin — gated on A3 evidence_status ────────────────────
{
  const healthy = sec(scorecardWith({ adminEv: "assessed_healthy" }), "Admin Surfaces");
  ok("admin: assessed_healthy + total0 → 'No exposed admin surfaces detected' + ok (A3 earned positive)",
    healthy.status === "ok" && /no exposed admin surfaces detected/i.test(healthy.summary));
  const unavail = sec(scorecardWith({ adminEv: "unavailable" }), "Admin Surfaces");
  ok("admin: unavailable + total0 → NEUTRAL 'could not be assessed', status unknown (never clean)",
    unavail.status === "unknown" && /could not be assessed/i.test(unavail.summary) && !/no exposed admin/i.test(unavail.summary));
  const notAssessed = sec(scorecardWith({ adminEv: "not_assessed" }), "Admin Surfaces");
  ok("admin: not_assessed + total0 → NEUTRAL 'not been assessed', unknown", notAssessed.status === "unknown" && /not been assessed yet/i.test(notAssessed.summary));
  const issue = sec(scorecardWith({ adminEv: "issue_detected", admin_surfaces: 2 }), "Admin Surfaces");
  ok("admin: total>0 → critical, issue surfaces", issue.status === "critical");
  const legacyNull = sec(scorecardWith({ adminEv: null, admin_surfaces: 0 }), "Admin Surfaces");
  ok("admin: legacy null evidence + total0 → NEUTRAL (never 'none detected')", legacyNull.status === "unknown" && !/no exposed admin surfaces detected/i.test(legacyNull.summary));
}

// ── 5. Legacy / empty payload does not crash ─────────────────────────────────
ok("legacy: empty cyber_mot_domains + null admin → sections build without crash, no false healthy",
  (() => {
    const secs = buildScorecardSections(scorecardWith({}));
    const brand = secs.find((s) => s.title === "Brand Monitoring");
    const admin = secs.find((s) => s.title === "Admin Surfaces");
    return Array.isArray(secs) && brand.status !== "ok" && admin.status !== "ok";
  })());

// ── 6. MUTATION HARNESS — helper gates are load-bearing ──────────────────────
// Inject a mutant helper into the REAL buildScorecardSections (rewrite scorecard.js
// imports to absolute; point scorecard-domain-state at the mutant).
const helperSrc = fs.readFileSync(HELPER, "utf8");
const scorecardSrc = fs.readFileSync(SCORECARD, "utf8");
async function mutantSections(mutateHelper) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "b-"));
  const hFile = path.join(dir, "helper.mjs");
  fs.writeFileSync(hFile, mutateHelper(helperSrc));
  const scSrc = scorecardSrc.replace(/from "\.\/([^"]+)"/g, (_m, f) =>
    f === "scorecard-domain-state.js" ? `from ${JSON.stringify(pathToFileURL(hFile).href)}` : `from ${JSON.stringify(absU(f))}`);
  const scFile = path.join(dir, "scorecard.mjs");
  fs.writeFileSync(scFile, scSrc);
  const mod = await import(`${pathToFileURL(scFile).href}?t=${Date.now()}-${Math.random()}`);
  fs.rmSync(dir, { recursive: true, force: true });
  return mod.buildScorecardSections;
}

// M1: unavailable → healthy.
{
  const m = helperSrc.includes('case "provisional":          return "unavailable";');
  const fn = m ? await mutantSections((s) => s.replace('case "provisional":          return "unavailable";', 'case "provisional":          return "healthy";')) : null;
  const cert = m ? sec(scorecardWith({ cmd: cmd("certificates_trust", "evidence_insufficient") }), "Certificate Intelligence", fn) : null;
  ok("mutation M1 (unavailable→healthy) is CAUGHT", m && (cert.status === "ok" || /looks normal/i.test(cert.summary)));
}
// M2: not_assessed → healthy (default case).
{
  const m = helperSrc.includes('return "not_assessed"; // not_yet_assessed');
  const fn = m ? await mutantSections((s) => s.replace('return "not_assessed"; // not_yet_assessed', 'return "healthy"; // not_yet_assessed')) : null;
  const sh = m ? sec(scorecardWith({ cmd: cmd("shadow_it_unmanaged_technology", "monitoring_only") }), "Third-Party Assets", fn) : null;
  ok("mutation M2 (not_assessed→healthy) is CAUGHT", m && (sh.status === "ok" || /no third-party/i.test(sh.summary)));
}
// M3: canSayHealthy always true (raw count zero bypasses canonical state).
{
  const m = helperSrc.includes('return scorecardBehaviour(state) === "healthy";');
  const fn = m ? await mutantSections((s) => s.replace('return scorecardBehaviour(state) === "healthy";', 'return true;')) : null;
  const brand = m ? sec(scorecardWith({ cmd: cmd("brand_protection", "evidence_insufficient") }), "Brand Monitoring", fn) : null;
  ok("mutation M3 (canSayHealthy always true → count bypasses state) is CAUGHT", m && /none currently resolving/i.test(brand.summary));
}
// M4: sectionStatus issue → ok (canonical issue suppressed by zero count).
{
  const m = helperSrc.includes('if (b === "issue")   return issueStatus;');
  const fn = m ? await mutantSections((s) => s.replace('if (b === "issue")   return issueStatus;', 'if (b === "issue")   return "ok";')) : null;
  const brand = m ? sec(scorecardWith({ cmd: cmd("brand_protection", "issue_detected") }), "Brand Monitoring", fn) : null;
  ok("mutation M4 (issue suppressed by zero count) is CAUGHT", m && brand.status === "ok");
}

console.log(`\nB scorecard canonical: ${pass}/${pass + fail} passed`);
if (fail) { console.error("b-scorecard-canonical validation FAILED"); process.exit(1); }
console.log("b-scorecard-canonical validation passed");
