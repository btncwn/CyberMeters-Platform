#!/usr/bin/env node
//
// M5.b remaining reconciliation — D1 (CE patch readiness), D2 (`external` support),
// D3 (ASM/Brand blanket drift). CI-blocking.
//
// ── D1 — the defect (LIVE, reproduced on a real production row) ──
// `patch_management_readiness` declared `external_coverage: partial` and published a NUMBER
// and a BAND carrying a third of the external readiness indicator — scored from certificate
// expiry, certificate risk, open critical/high ASM findings and asset-change events. NONE of
// those measures ANY of the four questions the control asks (auto-updates, unsupported
// removal, review process, 14-day critical patching). Production's own row proved it:
//   patch_management_readiness  cov=partial  state=not_ready  fingerprint=cert.intelligence.review
// A real workspace's "Security Update Management" was graded not-ready by a CERTIFICATE
// finding. It even published "No critical or high findings in the latest scan." as a POSITIVE
// reason for patch readiness — the same shape as "SPF is present." → Access Control 100/100.
//
// ── D2 ── `external` means an INDEPENDENT THIRD PARTY confirms it. It is not `automated`
// (CyberMeters' own observation) and not `manual` (the customer's word).
//
// ── D3 ── A blanket is safe only while EVERY underlying remediation derives the same
// support. ASM and Brand are aligned today by coincidence, not by construction.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcPath = (...p) => path.join(root, "workers", "scan-api", "src", ...p);
const eng = (f) => pathToFileURL(srcPath("engines", f)).href;

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const readiness = await import(eng("ce-readiness.js"));
const model = await import(eng("managed-case-model.js"));
const registry = await import(eng("remediation-registry.js"));
const ceLifecycle = await import(eng("ce-lifecycle.js"));
const ceCases = await import(eng("cyber-essentials-cases.js"));
const motDomains = await import(eng("cyber-mot-domains.js"));
const { CE_QUESTIONS } = await import(pathToFileURL(srcPath("lib", "cyber-essentials.js")).href);

// ── Harness: the REAL builder, one workspace, one scan report ───────────────
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

// The SAME site every time. Only the named certificate/ASM variable moves.
const REPORT = (over = {}) => ({ modules: {
  headers: { accessible: true, headers_assessed: true, values: { "strict-transport-security": "max-age=63072000", "content-security-policy": "default-src 'self'" }, present: [], missing: [] },
  ssl: { https_available: true, https_probe_executed: true, http_redirects_to_https: true, ...(over.ssl || {}) },
  email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
  ...(over.modules || {}),
} });
const POSITIVE_TLS_ABSENCE = Object.freeze({
  tls_state: "positively_absent",
  https_available: false,
  https_probe_executed: true,
  certificate_evidence: { observed_at: "2026-08-09T12:00:05.000Z" },
  tls_positive_absence_evidence: {
    state: "positively_absent",
    execution: "completed",
    source_type: "approved_active_tls_collector",
    collector: "m5b_contract_fixture",
    collector_version: "1",
    endpoint: "https://acme.example.com",
    assessed_domain: "acme.example.com",
    observed_at: "2026-08-09T12:00:00.000Z",
    absence_outcome: "tls_service_absent",
    evidence_grade: "positive_absence",
  },
});

async function run({ report = REPORT(), seed } = {}) {
  const db = buildDb();
  if (seed) seed(db);
  const env = { cybermeters_db: makeD1(db), cybermeters_reports: { get: async () => ({ json: async () => report }) } };
  return await readiness.buildCyberEssentialsReadiness("ws1", env);
}
const cat = (r, k) => r.categories.find((c) => c.key === k);
const PM = "patch_management_readiness";
const shape = (r) => { const c = cat(r, PM); return JSON.stringify({ score: c.score, band: c.band ?? null, weight: c.weight, assessed: c.externally_assessed, reasons: c.reasons, gaps: c.gaps, rem: c.remediations }); };

// ════ D1.1 — THE CONTROL IS NON-ASSESSABLE, ALWAYS ═══════════════════════════
{
  eq("the shared set declares patch_management_readiness non-assessable",
    CE_QUESTIONS.find((c) => c.control_key === PM).external_coverage, "none");
  eq("the readiness engine agrees", readiness.ceControlIsExternallyAssessable(PM), false);
  eq("the lifecycle agrees (one source of truth)", ceLifecycle.ceControlIsExternallyAssessable(PM), false);

  const r = await run();
  const c = cat(r, PM);
  eq("no numeric score", c.score, null);
  eq("no band", c.band ?? null, null);
  eq("zero readiness weight", c.weight, 0);
  eq("never externally assessed", c.externally_assessed, false);
  eq("assessable flag is false", c.assessable, false);
  eq("renders the honest state", c.reasons, [readiness.CE_NOT_ASSESSABLE_LABEL]);
  eq("carries no gaps", c.gaps, []);
  eq("carries no remediations", c.remediations, []);
  eq("carries no recommendations", c.recommendations, []);
  ok("it is still VISIBLE, not hidden", Boolean(c));
  eq("all five controls are still returned", r.categories.length, 5);
}

// ════ D1.2 — NO PROXY CAN MOVE IT ════════════════════════════════════════════
// Each variant changes exactly ONE proxy the control used to be scored from. The control's
// serialised shape must be byte-identical across every one of them.
{
  const base = await run();
  const baseShape = shape(base);

  const VARIANTS = {
    "certificate expired": { seed: (db) => db.prepare(`INSERT INTO certificate_observations (id,workspace_id,domain_id,certificate_key,expires_at,first_seen,last_seen)
      VALUES ('o1','ws1','d1','K1','2020-01-01T00:00:00Z',datetime('now'),datetime('now'))`).run() },
    "certificate expiring soon": { seed: (db) => db.prepare(`INSERT INTO certificate_observations (id,workspace_id,domain_id,certificate_key,expires_at,first_seen,last_seen)
      VALUES ('o2','ws1','d1','K2',datetime('now','+5 days'),datetime('now'),datetime('now'))`).run() },
    "certificate renewed (far future)": { seed: (db) => db.prepare(`INSERT INTO certificate_observations (id,workspace_id,domain_id,certificate_key,expires_at,first_seen,last_seen)
      VALUES ('o3','ws1','d1','K3',datetime('now','+800 days'),datetime('now'),datetime('now'))`).run() },
    "TLS gone entirely": { report: REPORT({ ssl: POSITIVE_TLS_ABSENCE }) },
    "critical + high ASM findings": { seed: (db) => {
      for (let i = 0; i < 4; i++) {
        db.prepare(`INSERT INTO findings (id,scan_id,severity,title,created_at)
                    VALUES (?, 'scan_1', ?, 'x', datetime('now'))`).run(`f${i}`, i < 2 ? "critical" : "high");
      }
    } },
    "asset change events": { seed: (db) => {
      db.prepare(`INSERT INTO workspace_assets (id,workspace_id,domain_id,hostname,asset_type,first_seen,last_seen,status,wildcard_dns,created_at,updated_at)
                  VALUES ('a1','ws1','d1','x.acme.example.com','subdomain',datetime('now'),datetime('now'),'active',0,datetime('now'),datetime('now'))`).run();
      db.prepare(`INSERT INTO asset_events (id,workspace_id,domain_id,asset_id,event_type,severity,created_at)
                  VALUES ('ae1','ws1','d1','a1','appeared','info',datetime('now'))`).run();
    } },
    "technology fingerprint / version disclosure": { report: REPORT({ modules: {
      technology_detection: { technologies: [{ name: "nginx", version: "1.14.0", categories: ["web-server"] }] },
    } }) },
  };
  for (const [name, v] of Object.entries(VARIANTS)) {
    const r = await run(v);
    eq(`${name}: cannot change Security Update Management`, shape(r), baseShape);
  }
  // And none of the removed proxies is even mentioned on the control any more.
  const blob = JSON.stringify(cat(base, PM)).toLowerCase();
  for (const w of ["certificate", "cert.", "expiry", "expire", "finding", "backlog", "asset change", "kev", "vulnerab"]) {
    ok(`no '${w}' attributed to Security Update Management`, !blob.includes(w), blob.slice(0, 140));
  }
  // The engine no longer even reads certificate expiry days.
  const src = fs.readFileSync(srcPath("engines", "ce-readiness.js"), "utf8");
  ok("the engine no longer computes certificate days-remaining for CE", !/certDaysLeft/.test(src));
  ok("no ssl_certificate_* finding is attributed anywhere in CE", !/ssl_certificate_expired|ssl_certificate_expiring_soon/.test(src));
}

// ════ D1.3 — THE 2-OF-5 CONTRACT ═════════════════════════════════════════════
{
  const r = await run();
  eq("exactly 2 assessable control areas", r.assessable_control_count, 2);
  eq("out of 5", r.total_control_count, 5);
  eq("the assessable two", r.categories.filter((c) => c.assessable).map((c) => c.key), ["boundary_protection", "secure_configuration"]);
  eq("the attestation three", r.categories.filter((c) => !c.assessable).map((c) => c.key).sort(),
    ["access_control", "malware_protection", PM]);
  eq("weights sum to exactly 100", Math.round(r.categories.reduce((s, c) => s + c.weight, 0) * 100) / 100, 100);
  const assessableScores = ["boundary_protection", "secure_configuration"].map((k) => cat(r, k).score);
  eq("the indicator is the mean of the assessable two ONLY",
    r.score, Math.round(assessableScores.reduce((a, b) => a + b, 0) / assessableScores.length));

  ok("the coverage statement says 2 of 5", /based on 2 of 5/.test(r.external_coverage_statement), r.external_coverage_statement);
  ok("it names all three attestation controls",
    /User Access Control/.test(r.external_coverage_statement)
    && /Malware Protection/.test(r.external_coverage_statement)
    && /Security Update Management/.test(r.external_coverage_statement), r.external_coverage_statement);
  ok("it is a sentence, not 'A and B and C'", !/and .* and /.test(r.external_coverage_statement), r.external_coverage_statement);
  ok("the limitations repeat the denominator", r.limitations.some((l) => /2 of 5/.test(l)));
  ok("nothing claims certification", !/certified|compliant/i.test(JSON.stringify(r.limitations.concat(r.summary))));
  // The three ATTESTATION controls must be named exactly as the questionnaire names them —
  // they are what the coverage sentence lists, and "Phishing & Malware Exposure" had drifted
  // from the set's "Malware Protection". The two assessable labels are deliberately left
  // alone: renaming "Boundary Protection" to the set's "Firewalls & Boundary Protection"
  // would be a customer-facing change this corrective was not asked to make.
  const sharedLabel = Object.fromEntries(CE_QUESTIONS.map((c) => [c.control_key, c.label]));
  for (const k of ["access_control", "malware_protection", PM]) {
    eq(`${k}: label comes from the questionnaire's own set`, cat(r, k).label, sharedLabel[k]);
  }
}

// ════ D1.4 — METHODOLOGY VERSION / REVISION / AS-OF, AND THE TREND RULE ══════
{
  const r = await run();
  ok("readiness_methodology_version is ISO 8601 YYYY-MM-DD", /^\d{4}-\d{2}-\d{2}$/.test(r.readiness_methodology_version));
  ok("readiness_methodology_revision is a positive integer",
    Number.isInteger(r.readiness_methodology_revision) && r.readiness_methodology_revision > 0);
  eq("this is revision 2 (the second material methodology correction)", r.readiness_methodology_revision, 2);
  ok("readiness_as_of is a real instant", Number.isFinite(Date.parse(r.readiness_as_of)));
  eq("the exported constants match the output", [readiness.CE_READINESS_METHODOLOGY_VERSION, readiness.CE_READINESS_METHODOLOGY_REVISION],
    [r.readiness_methodology_version, r.readiness_methodology_revision]);
  // It is NOT the questionnaire's version — two separate contracts.
  const { CE_QUESTION_SET_VERSION } = await import(pathToFileURL(path.join(root, "shared", "cyber-essentials-questions.js")).href);
  const stripJs = (x) => x.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  const src = stripJs(fs.readFileSync(srcPath("engines", "ce-readiness.js"), "utf8"));
  ok("methodology versioning does not overload the question-set version (two separate contracts)",
    !/CE_QUESTION_SET_VERSION/.test(src));

  // THE TREND RULE.
  const rev1 = { readiness_methodology_version: "2026-07-16", readiness_methodology_revision: 1, score: 84 };
  const rev2 = { readiness_methodology_version: "2026-07-16", readiness_methodology_revision: 2, score: 100 };
  eq("same version+revision => comparable", readiness.methodologyComparable(rev2, { ...rev2, score: 90 }), true);
  eq("a REVISION change => NOT comparable (the denominator moved, not the posture)",
    readiness.methodologyComparable(rev1, rev2), false);
  eq("a VERSION change => NOT comparable",
    readiness.methodologyComparable({ ...rev2, readiness_methodology_version: "2026-08-01" }, rev2), false);
  for (const missing of [{}, { readiness_methodology_version: "2026-07-16" }, { readiness_methodology_revision: 2 }, null]) {
    eq(`missing metadata (${JSON.stringify(missing)}) => NOT comparable — absent evidence of comparability is not evidence of it`,
      readiness.methodologyComparable(missing, rev2), false);
  }
  // THE case the null-guard actually exists for: TWO legacy values, neither carrying
  // metadata. A bare equality check would call null === null a match and compare two
  // readiness numbers produced by unknown, possibly different methodologies. Both being
  // silent is not both being the same.
  eq("two values that BOTH predate methodology versioning => NOT comparable",
    readiness.methodologyComparable({}, {}), false);
  eq("two nulls => NOT comparable", readiness.methodologyComparable(null, null), false);
  eq("two values with the same version but BOTH missing the revision => NOT comparable",
    readiness.methodologyComparable({ readiness_methodology_version: "2026-07-16" }, { readiness_methodology_version: "2026-07-16" }), false);
  // The historical value is PRESERVED, not rewritten: methodologyComparable is a pure read.
  const before = JSON.stringify(rev1);
  readiness.methodologyComparable(rev1, rev2);
  eq("comparing does not mutate the historical value", JSON.stringify(rev1), before);
}

// ════ D1.5 — THE PERSISTED DOMAIN TREND CANNOT REPORT A DEFINITION CHANGE ════
// The CE domain STATE derives from status -> grade -> score, whose denominator just changed.
// The portfolio trend compares per-domain states and gates on resolver_version, so that
// version MUST have moved or every customer's CE would "improve"/"deteriorate" on deploy day.
{
  eq("the Cyber MOT resolver version includes the combined SSL corrective boundary",
    motDomains.CYBER_MOT_RESOLVER_VERSION, "2026-08-09.2");
  const hist = await import(eng("cyber-mot-state-history.js"));
  const mk = (v, state) => ({ resolver_version: v, scan_quality: "complete", state, assessed_at: "2026-07-16T00:00:00Z" });
  const cross = hist.resolveDomainTrend(mk("2026-07-16.2", "assessed_healthy"), mk("2026-07-16.1", "issue_detected"));
  eq("a cross-version comparison is NOT_COMPARABLE, not an improvement", cross.trend, hist.DOMAIN_TREND.NOT_COMPARABLE);
  ok("and it says why in customer language, without blaming the customer",
    /changed between these two assessments/i.test(JSON.stringify(cross)), JSON.stringify(cross));
  // Same version => a real comparison still happens (the gate is not a blanket silencer).
  const same = hist.resolveDomainTrend(mk("2026-07-16.2", "assessed_healthy"), mk("2026-07-16.2", "issue_detected"));
  ok("a SAME-version comparison still produces a real trend", same.trend !== hist.DOMAIN_TREND.NOT_COMPARABLE, JSON.stringify(same));
}

// ════ D1.6 — ANSWERS STILL CANNOT REACH THE NUMBER, A CASE, OR AN ALERT ═════
{
  const withAnswers = (ans) => ({ seed: (db) => {
    for (const c of CE_QUESTIONS) for (const q of c.questions) {
      db.prepare(`INSERT INTO cyber_essentials_answers (id,workspace_id,control_key,question_key,answer,updated_at)
                  VALUES (?,?,?,?,?,datetime('now'))`).run(`a-${c.control_key}-${q.key}`, "ws1", c.control_key, q.key, ans);
    }
  } });
  const none = await run();
  for (const ans of ["yes", "no", "partial"]) {
    const r = await run(withAnswers(ans));
    eq(`all-${ans.toUpperCase()} answers cannot change the external indicator`, r.score, none.score);
    eq(`all-${ans.toUpperCase()} answers cannot change the coverage statement`, r.external_coverage_statement, none.external_coverage_statement);
    eq(`all-${ans.toUpperCase()} answers cannot give Security Update Management a score`, cat(r, PM).score, null);
  }
  // Answers reach neither the Cyber Metrics Score nor the Business Risk Indicator.
  const strip = (x) => x.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  for (const f of ["scoring.js", "business-risk.js", "posture-scoring.js"]) {
    ok(`${f} never reads cyber_essentials_answers`, !/cyber_essentials_answers/.test(strip(fs.readFileSync(srcPath("engines", f), "utf8"))));
  }
  // A questionnaire gap still cannot open a case, and PM cannot open one at all.
  const g = ceLifecycle.gradeCeControl({ key: PM, label: PM, remediations: [{ remediation_id: "cert.expiry.expired", customer_title: "x" }], unknown: [] });
  eq("Security Update Management grades not_externally_assessable even WITH cert gap evidence", g.state, "not_externally_assessable");
  eq("...and says why", g.reason, "control_not_externally_observable");
  eq("...and carries no fingerprint to band a recurrence on", g.fingerprint, null);
  ok("...so it can never open a managed case", !ceCases.CE_CASE_RECURRENCES.has(g.state));
}

// ════ D1.7 — STALE STORED ROWS ARE REINTERPRETED, NOT RE-RENDERED AS TRUTH ══
// Production holds a real row: patch_management_readiness cov=partial state=not_ready
// fingerprint=cert.intelligence.review. Until the next evaluation pass rewrites it, the read
// surface must not repeat a claim we have just retracted.
{
  const live = { id: "cec-1", control_key: PM, external_coverage: "partial", readiness_state: "not_ready",
                 readiness_reason: "external_evidence_shows_gaps", evidence_json: "[]", unknown_json: "[]" };
  const api = ceLifecycle.ceControlRecordToApi(live);
  eq("the stale row is served with the AUTHORITATIVE coverage", api.external_coverage, "none");
  eq("and the honest state", api.readiness_state, "not_externally_assessable");
  eq("and the honest reason", api.readiness_reason, "control_not_externally_observable");
  eq("what the row itself recorded is preserved, not overwritten", api.recorded_external_coverage, "partial");
  ok("the stale row is never rendered as externally verified", !/verified/i.test(JSON.stringify(api)));
  // An assessable control is untouched.
  const bp = ceLifecycle.ceControlRecordToApi({ id: "x", control_key: "boundary_protection", external_coverage: "partial", readiness_state: "not_ready", readiness_reason: "external_evidence_shows_gaps" });
  eq("an assessable control still serves its real state", [bp.external_coverage, bp.readiness_state], ["partial", "not_ready"]);
}

// ════ D2 — `external` IS ITS OWN SUPPORT ════════════════════════════════════
{
  const ext = registry.getRemediationById("ce.certification.external");
  eq("ce.certification.external declares the external method", ext.verification_method, "external");
  const kase = { id: "mc-e", workspace_id: "ws1", case_type: "cyber_essentials_case", remediation_id: "ce.certification.external", status: "awaiting_verification" };
  eq("`external` NEVER maps to automated", model.verificationSupportForCase(kase), "external");

  const attested = model.canTransitionCase({
    case: kase, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" },
    evidence: { verification_method: "manual_attestation", verification_result: "fixed", evidence_type: "customer_attestation",
                observed_at: new Date().toISOString(), attestation: { statement: "We are certified.", by: "u1" } },
  });
  ok("a customer attestation cannot satisfy external certification", !attested.ok);
  eq("refused for the right reason", attested.code, "verify_requires_external_evidence");

  const bySystem = model.canTransitionCase({
    case: kase, target_status: "verified", actor: { actor_type: "system", actor_id: null },
    evidence: { verification_method: "rescan", verification_result: "verified", evidence_type: "scan",
                observed_at: new Date().toISOString(), observation: { note: "looks fine" } },
  });
  ok("CyberMeters cannot conclude a third party's certification either", !bySystem.ok);
  eq("also refused as requiring external evidence", bySystem.code, "verify_requires_external_evidence");

  // No unreachable automated case: ce.certification.external cannot become a case today.
  const ce = await import(eng("ce-lifecycle.js"));
  const caseRems = Object.values(ce.CE_RECURRENCE_FINDING_TYPE).map((ft) => registry.resolveRemediation({ finding_type: ft }).remediation_id);
  ok("ce.certification.external is not reachable as a managed case", !caseRems.includes("ce.certification.external"), caseRems.join(","));
  eq("the only reachable CE case remediation", [...new Set(caseRems)], ["ce.readiness.control_review"]);

  // The label never borrows a reserved word, nor the customer's credit.
  const disp = await import(pathToFileURL(path.join(root, "frontend", "src", "lib", "caseDisplay.js")).href);
  const m = disp.phaseMeta("verified", "external");
  eq("external renders its own honest label", m.label, disp.EXTERNAL_EVIDENCE_LABEL);
  ok("it never says 'verified'", !/verified/i.test(m.label));
  ok("nor 'confirmed'", !/confirmed/i.test(m.label));
  ok("it is not green", m.tone !== "green");
  ok("it does not credit the customer with a third party's confirmation", !/attested by customer/i.test(m.label));

  // DRIFT GUARD: any future `external` remediation is caught here.
  const externals = registry.REMEDIATION_REGISTRY.filter((e) => e.status === "active" && e.verification_method === "external");
  eq("the known set of `external` remediations — a new one must be reviewed, not inherited",
    externals.map((e) => e.remediation_id), ["ce.certification.external"]);
  // Only the registry-DERIVED case types consult a remediation at all; a blanket case type
  // ignores it by definition, so asserting over those would be asserting nothing.
  for (const e of externals) {
    for (const ct of ["email_case", "website_case", "cyber_essentials_case", "certificate_case"]) {
      const s = model.verificationSupportForCase({ case_type: ct, remediation_id: e.remediation_id });
      eq(`${e.remediation_id} derives 'external' (never 'automated') under ${ct}`, s, "external");
    }
  }
}

// ════ D3 — ASM / BRAND / IDENTITY / SHADOW IT BLANKET DRIFT ══════════════════
// These four are NOT registry-derived. That is safe ONLY while every active remediation in
// the domain derives the SAME support as the blanket. This guard is what makes "safe by
// coincidence" into "safe by construction".
//
// Deriving ASM/Brand instead was considered and REJECTED with evidence: every real ASM
// case-creating finding shape (admin_surface_*, *takeover*, *cloud_storage*, exposed_*,
// canonical_url*, dse_*) resolves to NO remediation, so a derived asm_exposure case would
// carry remediation_id null and fail CLOSED to "unsupported" — every ASM case would become
// unverifiable. The blanket has no such failure mode. Guarding beats breaking a live domain.
{
  const derivedOf = (method) => method === "manual_attestation" ? "manual"
    : method === "unsupported" ? "unsupported"
    : method === "external" ? "external" : "automated";
  const BLANKET_DOMAINS = [
    ["attack_surface", "asm_exposure"],
    ["brand_protection", "brand_abuse"],
    ["identity_exposure", "identity_case"],
    ["shadow_it_unmanaged_technology", "shadow_it_case"],
  ];
  const DERIVED = ["email_case", "website_case", "cyber_essentials_case", "certificate_case"];
  for (const [dk, ct] of BLANKET_DOMAINS) {
    ok(`${ct} is NOT registry-derived (its blanket must therefore be guarded)`, !DERIVED.includes(ct));
    const blanket = model.CASE_TYPE_REGISTRY[ct].verification_support;
    const active = registry.REMEDIATION_REGISTRY.filter((e) => e.domain_key === dk && e.status === "active");
    ok(`${dk}: has remediations to check`, active.length > 0);
    const drift = active.filter((e) => derivedOf(e.verification_method) !== blanket)
      .map((e) => `${e.remediation_id}=${e.verification_method}->${derivedOf(e.verification_method)} (blanket ${blanket})`);
    eq(`${ct}: every remediation derives the same support as the blanket — a new manual/external/unsupported one must NOT silently inherit '${blanket}'`,
      drift, []);
  }
  // The derived four must stay derived.
  for (const ct of DERIVED) {
    ok(`${ct} remains registry-derived`,
      fs.readFileSync(srcPath("engines", "managed-case-model.js"), "utf8")
        .match(/REGISTRY_DERIVED_VERIFICATION = new Set\(\[[\s\S]*?\]\)/)[0].includes(ct));
  }
}

// ════ CROSS-DOMAIN REGRESSION — the evidence must survive where it belongs ══
{
  // Certificates keeps its own findings and verification.
  for (const id of ["cert.expiry.expired", "cert.expiry.expiring", "cert.intelligence.review", "cert.coverage_gap"]) {
    const e = registry.getRemediationById(id);
    ok(`${id} still exists in Certificates & Trust`, e && e.domain_key === "certificates_trust");
    eq(`${id} still verifies by CyberMeters' own observation`,
      model.verificationSupportForCase({ case_type: "certificate_case", remediation_id: id }), "automated");
  }
  // Attack Surface + Website Security evidence untouched.
  for (const [ft, dk] of [["asset_exposure_admin_interface", "attack_surface"],
                          ["header_missing_strict_transport_security", "website_security"],
                          ["ssl_not_available", "certificates_trust"]]) {
    const r = registry.resolveRemediation({ finding_type: ft });
    eq(`${ft} still resolves`, r.status, "resolved");
    eq(`${ft} still belongs to ${dk}`, r.domain_key, dk);
  }
  // The v2026.07.16-14 corrective did not regress.
  const r = await run();
  for (const k of ["access_control", "malware_protection"]) {
    eq(`${k}: still non-assessable (the -14 corrective holds)`, cat(r, k).score, null);
    eq(`${k}: still zero weight`, cat(r, k).weight, 0);
  }
  // Boundary + Secure Configuration still work and still grade.
  const gapped = await run({ report: REPORT({ ssl: POSITIVE_TLS_ABSENCE }) });
  ok("Boundary Protection still reacts to real evidence",
    cat(gapped, "boundary_protection").score !== cat(r, "boundary_protection").score
    || cat(gapped, "boundary_protection").gaps.length > 0);
  ok("Secure Configuration still grades", typeof cat(r, "secure_configuration").score === "number");
  const g = ceLifecycle.gradeCeControl({ key: "secure_configuration", label: "x", remediations: [{ remediation_id: "web.header.hsts", customer_title: "x" }], unknown: [] });
  eq("Secure Configuration recovery/grading still reachable", g.state, "not_ready");
  const gr = ceLifecycle.gradeCeControl({ key: "boundary_protection", label: "x", remediations: [], unknown: [] });
  eq("Boundary Protection can still reach ready (recovery reachable)", gr.state, "ready");
}

// ════ MUTATIONS ══════════════════════════════════════════════════════════════
if (!process.argv.includes("--no-mutate")) {
  const CE = srcPath("engines", "ce-readiness.js");
  const SHARED = path.join(root, "shared", "cyber-essentials-questions.js");
  const MODEL = srcPath("engines", "managed-case-model.js");
  const MOT = srcPath("engines", "cyber-mot-domains.js");
  const MUTATIONS = [
    { file: SHARED, name: "THE DEFECT: patch readiness is scoreable again",
      from: '    control_key: "patch_management_readiness",\n    external_coverage: "none",',
      to: '    control_key: "patch_management_readiness",\n    external_coverage: "partial",' },
    { file: CE, name: "certificate proxy returns to patch readiness",
      from: "  categories.push(cyberEssentialsCategory('patch_management_readiness', LABEL_FOR('patch_management_readiness'), 0, [], [], [], [], []));",
      to: "  categories.push({ key: 'patch_management_readiness', label: 'Patch Management Readiness', score: 100, weight: 20, assessable: true, externally_assessed: true, reasons: ['Certificate expiry health is acceptable.'], gaps: [], unknown: [], recommendations: [], remediations: [] });" },
    { file: CE, name: "ASM backlog proxy returns to patch readiness",
      from: "  categories.push(cyberEssentialsCategory('patch_management_readiness', LABEL_FOR('patch_management_readiness'), 0, [], [], [], [], []));",
      to: "  categories.push({ key: 'patch_management_readiness', label: 'Patch Management Readiness', score: 100, weight: 20, assessable: true, externally_assessed: true, reasons: ['No critical or high findings in the latest scan.'], gaps: [], unknown: [], recommendations: [], remediations: [] });" },
    { file: CE, name: "a non-assessable control regains readiness weight",
      from: "    weight: 0,              // Cannot influence the external-readiness indicator.",
      to: "    weight: 20," },
    { file: CE, name: "a non-assessable control regains a numeric score",
      from: "    score: null,            // NOT 0 and NOT 100: there is no number to publish.",
      to: "    score: 100," },
    { file: CE, name: "the coverage statement reverts to the old denominator",
      from: "  const assessableCategories = categories.filter((c) => c.assessable);",
      to: "  const assessableCategories = categories.filter((c) => c.assessable || c.key === 'patch_management_readiness');" },
    { file: CE, name: "the methodology revision is dropped",
      from: "    readiness_methodology_revision: CE_READINESS_METHODOLOGY_REVISION,", to: "" },
    { file: CE, name: "the methodology version is dropped",
      from: "    readiness_methodology_version: CE_READINESS_METHODOLOGY_VERSION,", to: "" },
    { file: CE, name: "cross-revision values are treated as a real trend",
      from: "  return A.ver === B.ver && A.rev === B.rev;", to: "  return A.ver === B.ver;" },
    { file: CE, name: "missing methodology metadata is treated as comparable",
      from: "  if (A.ver == null || B.ver == null || A.rev == null || B.rev == null) return false;", to: "" },
    { file: MOT, name: "the resolver version loses the combined SSL corrective boundary",
      from: 'export const CYBER_MOT_RESOLVER_VERSION = "2026-08-09.2";',
      to: 'export const CYBER_MOT_RESOLVER_VERSION = "2026-08-09.1";' },
    { file: MODEL, name: "`external` maps to automated again",
      from: '  if (method === "external") return "external";', to: "" },
    { file: MODEL, name: "external verification is accepted from a customer attestation",
      from: '    if (support === "external") {', to: "    if (false) {" },
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

console.log(`\nm5b-remaining-reconciliation: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
console.log("m5b-remaining-reconciliation validation passed");
