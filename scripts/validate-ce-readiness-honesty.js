#!/usr/bin/env node
//
// Cyber Essentials readiness honesty. DB-backed, drives the REAL buildCyberEssentialsReadiness.
// CI-blocking.
//
// The boundary this defends, stated once:
//
//   **Email authentication is not evidence of user access control.**
//   **Email authentication is not evidence of endpoint malware protection.**
//   **A control with no external coverage must never be rendered as externally healthy.**
//
// The defect this locks out was live: `access_control` and `malware_protection` declare
// `external_coverage: none`, yet were scored 0-100 from SPF/DKIM/DMARC, given colour bands
// and `externally_assessed: true`, and each carried 20% of the overall indicator. A business
// with perfect MFA scored 60/100 on "Access Control" for a missing SPF record; one with no
// MFA at all scored 100/100 in green.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcPath = (...p) => path.join(root, "workers", "scan-api", "src", ...p);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const NON_ASSESSABLE = ["access_control", "malware_protection"];
const ASSESSABLE = ["boundary_protection", "secure_configuration", "patch_management_readiness"];

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch {} };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u1','o@e.com','o','professional',datetime('now'))").run();
  db.prepare("UPDATE users SET email_verified=1").run();
  db.prepare(`INSERT INTO subscriptions (id,owner_user_id,plan,subscription_status,status,current_period_end,created_at,updated_at)
              VALUES ('s1','u1','professional','active','active',datetime('now','+30 days'),datetime('now'),datetime('now'))`).run();
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('ws1','u1','ws1')").run();
  db.prepare("INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES ('m1','ws1','u1','owner')").run();
  db.prepare("INSERT INTO domains (id,user_id,domain,created_at) VALUES ('d1','u1','acme.example.com',datetime('now'))").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws1','d1')").run();
  db.prepare(`INSERT INTO scans (id,domain_id,workspace_id,domain,score,rating,status,scan_quality,created_at)
              VALUES ('scan_1','d1','ws1','acme.example.com',70,'fair','completed','complete',datetime('now'))`).run();
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (c) => { const r = db.prepare(sql).get(...args) ?? null; return c && r ? r[c] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; },
    async batch(st) { return st.map((x) => ({ results: db.prepare(x.__sql).all(...(x.__args || [])), success: true, meta: {} })); },
  };
}
globalThis.fetch = async () => new Response("{}", { status: 200 });

// The SAME site every time; ONLY the email posture changes between variants. That is what
// isolates the proxy: any movement in a non-assessable control can only have come from email.
const site = (email) => ({ modules: {
  headers: { accessible: true, headers_assessed: true, values: { "strict-transport-security": "max-age=63072000", "content-security-policy": "default-src 'self'" }, present: [], missing: [] },
  ssl: { https_available: true, https_probe_executed: true, http_redirects_to_https: true },
  email_security: email,
} });
const EMAIL_VARIANTS = {
  perfect:   { spf: { present: true },  dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
  none:      { spf: { present: false }, dmarc: { present: false }, dkim: { present: false } },
  monitor:   { spf: { present: true },  dmarc: { present: true, policy: "none" },   dkim: { present: false } },
  unknown:   {},
};

const { buildCyberEssentialsReadiness, ceControlIsExternallyAssessable, CE_NOT_ASSESSABLE_LABEL } =
  await import(pathToFileURL(srcPath("engines", "ce-readiness.js")).href);
const { CE_QUESTIONS } = await import(pathToFileURL(srcPath("lib", "cyber-essentials.js")).href);

async function readiness(emailVariant) {
  const db = buildDb();
  const REPORT = site(EMAIL_VARIANTS[emailVariant]);
  const env = { cybermeters_db: makeD1(db), cybermeters_reports: { get: async () => ({ json: async () => REPORT }) } };
  return await buildCyberEssentialsReadiness("ws1", env);
}
const cat = (r, k) => r.categories.find((c) => c.key === k);

// ════ 1. COVERAGE IS THE REPO'S OWN METADATA, AND ONE SOURCE OF TRUTH ═══════
{
  eq("five canonical CE controls", CE_QUESTIONS.length, 5);
  for (const q of CE_QUESTIONS) {
    const expected = NON_ASSESSABLE.includes(q.control_key) ? "none" : "partial";
    eq(`${q.control_key}: declared external_coverage`, q.external_coverage || "none", expected);
    eq(`${q.control_key}: readiness agrees on assessability`,
      ceControlIsExternallyAssessable(q.control_key), expected === "partial");
  }
  // The scoring path and the managed-case path must never disagree about what we can see.
  const lifecycle = await import(pathToFileURL(srcPath("engines", "ce-lifecycle.js")).href);
  for (const q of CE_QUESTIONS) {
    eq(`${q.control_key}: readiness and lifecycle agree on assessability`,
      ceControlIsExternallyAssessable(q.control_key), lifecycle.ceControlIsExternallyAssessable(q.control_key));
  }
}

// ════ 2. EMAIL AUTH CANNOT MOVE EITHER CONTROL — THE CORE CLAIM ═════════════
{
  const results = {};
  for (const v of Object.keys(EMAIL_VARIANTS)) results[v] = await readiness(v);

  for (const key of NON_ASSESSABLE) {
    const shapes = Object.entries(results).map(([v, r]) => {
      const c = cat(r, key);
      return [v, JSON.stringify({ score: c.score, band: c.band ?? null, externally_assessed: c.externally_assessed, reasons: c.reasons, gaps: c.gaps, weight: c.weight })];
    });
    const first = shapes[0][1];
    for (const [v, s] of shapes) {
      eq(`${key}: identical under email posture '${v}' (SPF/DKIM/DMARC cannot move it)`, s, first);
    }
    // And identical means identically HONEST, not identically wrong.
    for (const [v, r] of Object.entries(results)) {
      const c = cat(r, key);
      eq(`${key} @${v}: publishes NO numeric score`, c.score, null);
      eq(`${key} @${v}: publishes no band`, c.band ?? null, null);
      eq(`${key} @${v}: externally_assessed is false`, c.externally_assessed, false);
      eq(`${key} @${v}: assessable is false`, c.assessable, false);
      eq(`${key} @${v}: weight is zero`, c.weight, 0);
      eq(`${key} @${v}: renders the honest label`, c.reasons, [CE_NOT_ASSESSABLE_LABEL]);
      eq(`${key} @${v}: carries no gaps`, c.gaps, []);
      eq(`${key} @${v}: carries no remediations`, c.remediations, []);
      eq(`${key} @${v}: carries no recommendations`, c.recommendations, []);
      // No email-auth wording may be attributed to it, in any field.
      const blob = JSON.stringify(c).toLowerCase();
      for (const w of ["spf", "dkim", "dmarc", "anti-spoofing", "spoof"]) {
        ok(`${key} @${v}: no '${w}' attributed anywhere on the control`, !blob.includes(w), blob.slice(0, 160));
      }
      // And no positive/health wording.
      ok(`${key} @${v}: claims no health`, !/is present|detected|acceptable|no major readiness gaps|strong/i.test(JSON.stringify(c.reasons)));
    }
  }
  // The assessable controls DID stay put too — proving the harness changed only email.
  for (const key of ASSESSABLE) {
    const scores = Object.values(results).map((r) => cat(r, key).score);
    eq(`${key}: unaffected by email posture (the site never changed)`, new Set(scores).size, 1);
  }
}

// ════ 3. THE ARITHMETIC AND THE DENOMINATOR ═════════════════════════════════
{
  const r = await readiness("perfect");
  eq("exactly 3 assessable control areas", r.assessable_control_count, 3);
  eq("out of 5 total", r.total_control_count, 5);
  eq("only assessable areas carry weight",
    r.categories.filter((c) => c.weight > 0).map((c) => c.key).sort(), [...ASSESSABLE].sort());
  eq("non-assessable areas carry zero weight",
    r.categories.filter((c) => c.weight === 0).map((c) => c.key).sort(), [...NON_ASSESSABLE].sort());
  eq("weights sum to exactly 100", Math.round(r.categories.reduce((s, c) => s + c.weight, 0) * 100) / 100, 100);

  // The indicator is the mean of the ASSESSABLE areas — nothing else.
  const assessableScores = ASSESSABLE.map((k) => cat(r, k).score);
  eq("the indicator is the mean of the assessable areas only",
    r.score, Math.round(assessableScores.reduce((a, b) => a + b, 0) / assessableScores.length));

  // Both controls are still VISIBLE — hiding them would be its own dishonesty.
  eq("all five control areas are still returned", r.categories.length, 5);
  for (const k of NON_ASSESSABLE) ok(`${k} is still shown, not hidden`, Boolean(cat(r, k)));

  // The coverage statement is present, accurate and names both controls.
  ok("a coverage statement is published", Boolean(r.external_coverage_statement));
  ok("it states the real denominator (3 of 5)", /3 of 5/.test(r.external_coverage_statement), r.external_coverage_statement);
  ok("it names Access Control", /Access Control/.test(r.external_coverage_statement));
  ok("it names the malware control", /Malware/i.test(r.external_coverage_statement));
  ok("it says they need attestation", /attestation/i.test(r.external_coverage_statement));
  eq("non_assessable_controls lists exactly the two", r.non_assessable_controls.map((c) => c.key).sort(), [...NON_ASSESSABLE].sort());
  ok("the coverage statement rides in limitations too", r.limitations.some((l) => /3 of 5/.test(l)));
  // Never imply certification.
  ok("nothing claims certification or compliance",
    !/certified|compliant|certification achieved/i.test(JSON.stringify({ s: r.summary, st: r.status, l: r.limitations })));
  ok("limitations still say CyberMeters does not certify", r.limitations.some((l) => /does not certify/i.test(l)));

  // A DIFFERENT email posture must not move the overall indicator either.
  const r2 = await readiness("none");
  eq("the overall indicator is identical with email auth removed", r2.score, r.score);
  eq("and the coverage statement is unchanged", r2.external_coverage_statement, r.external_coverage_statement);
}

// ════ 4. STRENGTHS / TOP ACTIONS / RECOMMENDATIONS ══════════════════════════
{
  for (const v of ["perfect", "none", "monitor"]) {
    const r = await readiness(v);
    // No CE top gap or recommendation may exist that only the removed proxies produced.
    const blob = JSON.stringify({ g: r.top_gaps, rec: r.recommendations, rem: r.canonical_remediations });
    ok(`@${v}: no CE top gap attributes access control to email auth`,
      !/access-control exposure/i.test(blob), blob.slice(0, 200));
    ok(`@${v}: no CE gap claims email auth is malware protection`,
      !/malware delivery risk/i.test(blob), blob.slice(0, 200));
    // ce_saas_access_review was attributed ONLY to access_control; it must be gone from CE.
    ok(`@${v}: the SaaS access-review remediation is no longer attributed to CE access control`,
      !/ce_saas_access_review/.test(blob));
  }
}

// ════ 5. QUESTIONNAIRE ANSWERS DO NOT MOVE THE INDICATOR ════════════════════
// The external indicator is built from external evidence. buildCyberEssentialsReadiness
// never reads cyber_essentials_answers (mig 090's own comment says so) — asserted here so a
// future change cannot quietly wire attestation into a number called "external".
{
  const src = fs.readFileSync(srcPath("engines", "ce-readiness.js"), "utf8");
  const builder = src.slice(src.indexOf("export async function buildCyberEssentialsReadiness"), src.indexOf("export function isCyberEssentialsQuestionnaireComplete"));
  ok("the external readiness builder never reads questionnaire answers",
    !/cyber_essentials_answers/.test(builder));
  // And answers reach neither the Cyber Metrics Score nor the Business Risk Indicator.
  for (const f of ["scoring.js", "business-risk.js", "posture-scoring.js"]) {
    ok(`${f} never reads cyber_essentials_answers`,
      !/cyber_essentials_answers/.test(fs.readFileSync(srcPath("engines", f), "utf8")));
  }
}

// ════ 6. THE EXECUTIVE PDF CANNOT PRINT 100/100 FOR EITHER CONTROL ══════════
{
  const pdf = fs.readFileSync(srcPath("engines", "pdf.js"), "utf8");
  const sec = pdf.slice(pdf.indexOf("Observed Control Area Breakdown"), pdf.indexOf("Observed Control Area Breakdown") + 3400);
  ok("the PDF reads the assessable flag", /catAssessable/.test(sec));
  ok("a non-assessable area yields no score to print", /catAssessable \? \(catData\?\.score \?\? null\) : null/.test(sec));
  ok("the PDF prints the honest label instead of a number",
    sec.includes("Not externally assessable — self-attestation only"));
  ok("the PDF prints the coverage statement", /external_coverage_statement/.test(sec));
  // The band is derived from catScore, which is null for a non-assessable area => 'unknown'
  // => grey. Proven by construction rather than asserted: there is no other source.
  ok("the colour band is derived only from the score", /const catStatus= catScore == null \? 'unknown'/.test(sec));

  // Drive the real category data through the PDF's own status derivation.
  const r = await readiness("perfect");
  for (const k of NON_ASSESSABLE) {
    const c = cat(r, k);
    const catAssessable = c.assessable !== false;
    const catScore = catAssessable ? (c.score ?? null) : null;
    eq(`PDF: ${k} has no score to render`, catScore, null);
    const catStatus = catScore == null ? "unknown" : catScore >= 80 ? "good" : "fair";
    eq(`PDF: ${k} cannot be green`, catStatus, "unknown");
  }
  for (const k of ASSESSABLE) {
    const c = cat(r, k);
    ok(`PDF: ${k} still renders its justified number`, typeof c.score === "number");
  }
}

// ════ 7. THE FRONTEND CONSUMES, IT DOES NOT DERIVE ══════════════════════════
{
  const page = fs.readFileSync(path.join(root, "frontend", "src", "pages", "ws", "WorkspaceCyberEssentialsPage.jsx"), "utf8");
  ok("the page consumes the backend coverage statement", /readiness\?\.external_coverage_statement/.test(page));
  ok("the page does not compute its own coverage", !/assessable_control_count\s*=|filter\(.*assessable/.test(page));
  ok("an absent indicator is neutral, not red",
    /typeof score !== 'number'\) return 'border-gray-200/.test(page));
  ok("the label says EXTERNAL readiness, not bare 'readiness'", /External readiness indicator/.test(page));
  ok("the number is only shown when it is a number", /typeof readiness\?\.score === 'number'/.test(page));
  // The public page is a SELF-ASSESSMENT and must never claim external checking.
  const pub = fs.readFileSync(path.join(root, "frontend", "src", "pages", "CyberEssentialsReadinessPage.jsx"), "utf8");
  ok("the public page labels un-checked controls honestly", /not_externally_checked/.test(pub));
  ok("the public page distinguishes self-declared answers", /self_declared/.test(pub));
}

// ════ 8. PR3 CASE/LIFECYCLE BEHAVIOUR IS NOT REGRESSED ══════════════════════
// The managed-case path was ALREADY honest and must stay exactly as it was.
{
  const lifecycle = await import(pathToFileURL(srcPath("engines", "ce-lifecycle.js")).href);
  const cases = await import(pathToFileURL(srcPath("engines", "cyber-essentials-cases.js")).href);
  for (const key of NON_ASSESSABLE) {
    const g = lifecycle.gradeCeControl({ key, label: key, remediations: [{ remediation_id: "x", customer_title: "x" }], unknown: [] });
    eq(`${key}: still grades not_externally_assessable`, g.state, "not_externally_assessable");
    eq(`${key}: still never actionable`, g.state === "not_ready", false);
    ok(`${key}: still cannot open a case`, !cases.CE_CASE_RECURRENCES.has(g.state));
  }
  for (const key of ASSESSABLE) {
    const g = lifecycle.gradeCeControl({ key, label: key, remediations: [{ remediation_id: "ce.x", customer_title: "x" }], unknown: [] });
    eq(`${key}: still grades not_ready on real gap evidence`, g.state, "not_ready");
  }
  // The recovery contract is untouched.
  eq("control_recovered is still CE's recovery event", cases.CE_RECOVERY_EVENT, lifecycle.CE_EVENT_RECOVERED);
  eq("both CE recurrences still open cases", [...cases.CE_CASE_RECURRENCES].length, 2);
}

// ════ 9. MUTATIONS ══════════════════════════════════════════════════════════
if (!process.argv.includes("--no-mutate")) {
  const CE = srcPath("engines", "ce-readiness.js");
  const PDF = srcPath("engines", "pdf.js");
  const PAGE = path.join(root, "frontend", "src", "pages", "ws", "WorkspaceCyberEssentialsPage.jsx");
  const MUTATIONS = [
    { file: CE, name: "the two controls are reintroduced into the score arithmetic",
      from: "  const assessableCategories = categories.filter((c) => c.assessable);",
      to: "  const assessableCategories = categories.slice();" },
    { file: CE, name: "externally_assessed becomes true for a non-assessable control",
      from: "    externally_assessed: false,\n    external_coverage: \"none\",",
      to: "    externally_assessed: true,\n    external_coverage: \"none\"," },
    { file: CE, name: "a numeric score is published for a non-assessable control",
      from: "    score: null,            // NOT 0 and NOT 100: there is no number to publish.",
      to: "    score: 100," },
    { file: CE, name: "a green band is published for a non-assessable control",
      from: "    band: null,", to: "    band: 'good'," },
    { file: CE, name: "the coverage disclaimer is removed",
      from: "    external_coverage_statement: coverageStatement,", to: "" },
    { file: CE, name: "email-auth reasons are re-attributed to Access Control",
      from: "  categories.push(cyberEssentialsCategory('access_control', 'Access Control', 0, [], [], [], [], []));",
      to: "  categories.push({ key: 'access_control', label: 'Access Control', score: 100, weight: 20, assessable: true, externally_assessed: true, reasons: ['SPF is present.'], gaps: [], unknown: [], recommendations: [], remediations: [] });" },
    { file: CE, name: "email-auth reasons are re-attributed to Malware Protection",
      from: "  categories.push(cyberEssentialsCategory('malware_protection', 'Phishing & Malware Exposure', 0, [], [], [], [], []));",
      to: "  categories.push({ key: 'malware_protection', label: 'Phishing & Malware Exposure', score: 100, weight: 20, assessable: true, externally_assessed: true, reasons: ['DMARC is present.'], gaps: [], unknown: [], recommendations: [], remediations: [] });" },
    { file: CE, name: "the coverage gate is bypassed so proxies score the control again",
      from: "  if (!ceControlIsExternallyAssessable(key)) return cyberEssentialsNonAssessableCategory(key, label);",
      to: "" },
    { file: PDF, name: "the PDF uses the old five-control numeric breakdown",
      from: "      const catScore = catAssessable ? (catData?.score ?? null) : null;",
      to: "      const catScore = catData?.score ?? 100;" },
    { file: PAGE, name: "the frontend derives a positive verdict from an absent score",
      from: "  if (typeof score !== 'number') return 'border-gray-200 bg-gray-50 text-gray-700'",
      to: "  if (typeof score !== 'number') return 'border-brand-100 bg-brand-50 text-brand-800'" },
    { file: PAGE, name: "the frontend drops the coverage statement",
      from: "            {readiness?.external_coverage_statement ? (", to: "            {false ? (" },
  ];
  const self = fileURLToPath(import.meta.url);
  const { execFileSync } = await import("node:child_process");
  for (const m of MUTATIONS) {
    const orig = fs.readFileSync(m.file, "utf8");
    ok(`mutation applies: ${m.name}`, orig.includes(m.from), "anchor not found — the mutation tests nothing");
    if (!orig.includes(m.from)) continue;
    fs.writeFileSync(m.file, orig.replace(m.from, m.to));
    let survived = true;
    try { execFileSync(process.execPath, [self, "--no-mutate"], { stdio: "pipe" }); } catch { survived = false; }
    finally { fs.writeFileSync(m.file, orig); }
    ok(`mutation is CAUGHT: ${m.name}`, !survived, "the suite stayed green — this guard proves nothing");
  }
}

console.log(`\nce-readiness-honesty: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
console.log("ce-readiness-honesty validation passed");
