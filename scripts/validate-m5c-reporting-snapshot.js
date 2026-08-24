#!/usr/bin/env node
//
// M5.c — Canonical reporting snapshot contract (migration 093 + report-snapshot.js).
//
// Locks out these defect classes:
//   A. Eight-domain completeness — a snapshot that drops a domain, adds a ninth
//      ("Admin Exposure"), or resurrects a five-pillar registry as a customer
//      section (intelligence_engines / Vendor Risk / Supply Chain).
//   B. Immutability — a completed snapshot being overwritten or rebuilt; a later
//      scan mutating history instead of superseding it append-only; a read path
//      that recalculates historical content with today's engines.
//   C. Idempotency / concurrency / partial failure — two builders both becoming
//      canonical; a failed R2 write leaving a D1 row that claims completion; a
//      half-written snapshot exposed as completed.
//   D. Truth consistency — snapshot content disagreeing with the canonical
//      resolvers at build time; CE's 2-of-5 contract silently undone;
//      questionnaire answers reaching the Cyber Metrics Score; unknown/
//      insufficient evidence becoming healthy.
//   E. Remediation — invented copy for unmapped findings; loss of the
//      one-action-many-findings linkage; verification_support/ceiling drift
//      ("Verified" wording on customer attestation).
//   F. Methodology — version stamps dropped so a methodology change reads as a
//      posture change.
//   G. Tenant/data safety — cross-tenant snapshot reads; purge leaving snapshot
//      R2 objects or rows behind; soft-deleted workspaces receiving snapshots.
//   H. Vocabulary — BRI presented as a score; "Verified"/"Confirmed" outside
//      system-observed support.
//
// Runs the REAL builder against a REAL in-memory SQLite (schema + migrations)
// and a recording R2 stub with injectable failures. Ends with source-mutation
// tests: each guard is proven by reintroducing its defect and requiring THIS
// suite to fail (--no-mutate skips the mutation stage in the child).
//
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcPath = (...p) => path.join(root, "workers", "scan-api", "src", ...p);
const self = fileURLToPath(import.meta.url);

globalThis.fetch = async () => { throw new Error("network disabled"); };
AbortSignal.timeout = () => undefined;

let pass = 0, fail = 0;
function ok(name, cond, hint) {
  if (cond) { pass++; }
  else { fail++; console.log(`FAIL ${name}${hint ? ` — ${hint}` : ""}`); }
}

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* additive drift tolerated */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  return db;
}

function makeD1(db, flags) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run:   async () => {
      if (flags?.d1FinalizeFail && /SET status = 'completed'/.test(sql)) throw new Error("injected D1 failure");
      const r = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } };
    },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

// Recording R2 stub: serves seeded scan reports (so CE readiness can grade),
// records puts/deletes, and fails on demand.
function makeR2(store, flags, recorded) {
  return {
    get: async (key) => {
      const body = store.get(key);
      if (body == null) return null;
      return { json: async () => JSON.parse(body), text: async () => body };
    },
    put: async (key, body, opts) => {
      if (flags.r2Fail) throw new Error("injected R2 failure");
      recorded.puts.push({ key, body: String(body), opts });
      store.set(key, String(body));
      return {};
    },
    delete: async (key) => { recorded.deletes.push(key); store.delete(key); return {}; },
    head: async () => null,
    list: async () => ({ objects: [] }),
  };
}

// ── A realistic completed-scan report ────────────────────────────────────────
// Modules cover every resolver-required module so a 'complete' scan can resolve
// healthy where no material finding maps. Findings:
//   • email_missing_spf   — material, automated verification (dns_recheck)
//   • sender_unrecognised-shaped manual finding is exercised via case rows
//   • zz_unknown_finding  — a type the registry cannot resolve (fail-closed path)
//   • an info observation — must land in `observations`, not Observed Findings
function makeReport(scanId, domainId, domain, opts = {}) {
  const quality = opts.quality ?? "complete";
  const modules = opts.modules ?? {
    dns: { has_mx: true }, email_security: { spf: null }, headers: {}, ssl: {},
    subdomains: { count: 1 }, certificate_intelligence: { total_certificates: 1 },
    brand_monitoring: { candidates: [] }, identity_discovery: { high_risk_count: 0 },
    technology_detection: { count: 2 }, saas_exposure: { count: 0 },
    third_party_assets: { count: 0 }, vendor_relationships: { high_confidence: 0 },
    whois_intelligence: {},
  };
  const findings = opts.findings ?? [
    { id: "email_missing_spf", title: "SPF record missing", description: "No SPF record was found for this domain.", severity: "high", module: "email_security", finding_type: "finding", evidence: [{ type: "dns_lookup" }] },
    { id: "zz_unknown_finding", title: "Unmapped condition", description: "A condition with no canonical remediation.", severity: "medium", module: "headers", finding_type: "finding", evidence: [] },
    { id: "tls_ciphers_info", title: "TLS observation", description: "Informational TLS observation.", severity: "info", module: "ssl", finding_type: "observation", evidence: [] },
  ];
  return {
    scan_id: scanId, domain_id: domainId, domain, status: "completed",
    cyber_metrics_score: 62, risk_level: "moderate",
    started_at: "2026-07-16T10:00:00.000Z", completed_at: opts.completedAt ?? "2026-07-16T10:05:00.000Z",
    findings, recommendations: [],
    scan_quality: { status: quality, modules_skipped: opts.skipped ?? [], warnings: [] },
    monitoring_states: {
      version: "signal-monitoring-state-v1",
      signals: Object.fromEntries([
        "dns",
        "certificate_transparency",
        "website_security",
        "email_protection",
        "attack_surface",
        "technology_visibility",
        "vulnerability_intelligence",
        "registration_data",
      ].map((signal) => [signal, {
        state: "monitoring_healthy",
        message: `${signal} checks completed normally in this run.`,
        evidence: { modules: [], incomplete_modules: [], providers: {} },
      }])),
    },
    modules,
  };
}

async function main() {
  const snapEngine = await import(pathToFileURL(srcPath("engines", "report-snapshot.js")).href);
  const { buildScanReportSnapshot, composeSnapshot, snapshotSha256Hex, verificationCeiling,
          SNAPSHOT_SCHEMA_VERSION, SNAPSHOT_BUILDER_VERSION, EVIDENCE_GRADES,
          EVIDENCE_SOURCE_TYPES } = snapEngine;
  const { resolveCyberMotDomainStates, CYBER_MOT_RESOLVER_VERSION } = await import(pathToFileURL(srcPath("engines", "cyber-mot-domains.js")).href);
  const { CYBER_MOT_DOMAIN_KEYS } = await import(pathToFileURL(srcPath("engines", "cyber-mot-state-history.js")).href);
  const { deriveScanBusinessRisk, BUSINESS_RISK_METHODOLOGY_VERSION } = await import(pathToFileURL(srcPath("engines", "business-risk.js")).href);
  const { CYBER_METRICS_SCORE_METHODOLOGY_VERSION } = await import(pathToFileURL(srcPath("engines", "scoring.js")).href);
  const { CE_QUESTION_SET_VERSION } = await import(pathToFileURL(srcPath("lib", "cyber-essentials.js")).href);
  const { remediationRegistryFingerprint, listRegisteredFindingTypes, resolveRemediation } = await import(pathToFileURL(srcPath("engines", "remediation-registry.js")).href);
  // The whole worker: real fetch handler (route contract tests) + the purge engine.
  const workerMod = await import(pathToFileURL(srcPath("index.js")).href);
  const worker = workerMod.default;
  const { hashToken, hashPassword, purgeWorkspaceData } = workerMod;

  const db = buildDb();
  const flags = { r2Fail: false, d1FinalizeFail: false };
  const store = new Map();
  const recorded = { puts: [], deletes: [] };
  const env = {
    cybermeters_db: makeD1(db, flags),
    cybermeters_reports: makeR2(store, flags, recorded),
    RESEND_API_KEY: "", APP_VERSION: "test",
  };

  // ── Seed: two tenants sharing a hostname, one soft-deleted tenant ──────────
  db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified, mfa_enabled) VALUES ('u1','o@a.co','x','O','free','active',1,0)").run();
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws1','u1','Alpha')").run();
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws2','u1','Bravo')").run();
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name, deleted_at) VALUES ('wsDead','u1','Dead', datetime('now'))").run();
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom1','u1','shared.example')").run();
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom2','u1','shared.example')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws1','dom1')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws2','dom2')").run();

  const seedScan = (id, wsId, domId) => {
    db.prepare("INSERT INTO scans (id, workspace_id, domain_id, domain, score, rating, status, scan_quality, created_at) VALUES (?,?,?,?,62,'moderate','completed','complete',datetime('now'))")
      .run(id, wsId, domId, "shared.example");
  };
  seedScan("scan1", "ws1", "dom1");
  const report1 = makeReport("scan1", "dom1", "shared.example");
  store.set("reports/scan1.json", JSON.stringify(report1));

  // A complete CE questionnaire (all 20 answers) so the CE state resolves and
  // question_set_version travels; answers deliberately GOOD internal controls so
  // any leakage into the score would move it.
  const { CE_QUESTIONS } = await import(pathToFileURL(path.join(root, "shared", "cyber-essentials-questions.js")).href).catch(() => ({ CE_QUESTIONS: null }));
  if (CE_QUESTIONS) {
    for (const ctrl of CE_QUESTIONS) {
      for (const q of ctrl.questions) {
        db.prepare("INSERT INTO cyber_essentials_answers (id, workspace_id, control_key, question_key, answer, question_set_version, updated_at) VALUES (?,?,?,?,?,?,datetime('now'))")
          .run(`cea-${ctrl.control_key}-${q.key}`, "ws1", ctrl.control_key, q.key, "yes", "2026-07-16");
      }
    }
  }
  ok("CE question module loaded (questionnaire seeding is real)", !!CE_QUESTIONS);

  // A managed case linked to the SPF finding (automated support via dns_recheck).
  db.prepare(`INSERT INTO managed_cases (id, workspace_id, case_type, domain_key, domain, finding_id, remediation_id, severity, status, evidence_json, recommended_actions_json, created_at, updated_at)
              VALUES ('mc1','ws1','email_case','email_protection','shared.example','email_missing_spf','email.spf.publish','high','open','{}','[]',datetime('now'),datetime('now'))`).run();

  const ceSnapFor = async (wsId) => {
    const { getCyberEssentialsSnapshot } = await import(pathToFileURL(srcPath("engines", "ce-readiness.js")).href);
    try { return await getCyberEssentialsSnapshot(wsId, env); } catch { return null; }
  };

  // ═══ A. Build + eight-domain completeness ═══════════════════════════════════
  const ceSnap1 = await ceSnapFor("ws1");
  const res1 = await buildScanReportSnapshot(env, {
    workspaceId: "ws1", domainId: "dom1", scanId: "scan1", domain: "shared.example",
    report: report1, cyberEssentials: ceSnap1, assessedAt: report1.completed_at,
  });
  ok("first build completes", res1.status === "completed", JSON.stringify(res1));
  const put1 = recorded.puts.find((p) => p.key.includes("scan1"));
  ok("snapshot JSON persisted to a tenant-prefixed R2 key",
     !!put1 && put1.key.startsWith("reports/snapshots/ws1/scan1/"));
  const snap1 = put1 ? JSON.parse(put1.body) : null;

  ok("exactly eight domains, canonical keys, fixed order",
     !!snap1 && Array.isArray(snap1.domains) &&
     JSON.stringify(snap1.domains.map((d) => d.domain_key)) === JSON.stringify([...CYBER_MOT_DOMAIN_KEYS]));
  const domainKeySet = new Set((snap1?.domains ?? []).map((d) => d.domain_key));
  ok("no ninth Admin Exposure domain", !domainKeySet.has("admin_exposure"));
  ok("no Vendor Risk / Supply Chain customer domains",
     !domainKeySet.has("vendor_risk") && !domainKeySet.has("supply_chain") && !domainKeySet.has("third_party_risk"));
  ok("no five-pillar intelligence_engines section", snap1 && !("intelligence_engines" in snap1));
  ok("no five-category posture registry as a customer section",
     snap1 && !("posture_categories" in snap1) && !Object.keys(snap1).includes("ssl_certificates"));

  // Value equality on EVERY stamp — a stale hardcoded constant would defeat the
  // stamps' whole purpose (methodology change reading as posture change).
  ok("methodology block carries every stamp, by VALUE",
     snap1?.methodology?.cyber_mot_resolver_version === CYBER_MOT_RESOLVER_VERSION &&
     snap1?.methodology?.cyber_metrics_score_methodology_version === CYBER_METRICS_SCORE_METHODOLOGY_VERSION &&
     snap1?.methodology?.business_risk_methodology_version === BUSINESS_RISK_METHODOLOGY_VERSION &&
     snap1?.methodology?.snapshot_builder_version === SNAPSHOT_BUILDER_VERSION &&
     snap1?.methodology?.ce_question_set_version === CE_QUESTION_SET_VERSION &&
     JSON.stringify(snap1?.methodology?.ce_question_set_versions) === JSON.stringify(["2026-07-16"]) &&
     snap1?.methodology?.remediation_registry_fingerprint === remediationRegistryFingerprint());
  ok("snapshot schema version stamped", snap1?.snapshot?.snapshot_schema_version === SNAPSHOT_SCHEMA_VERSION);
  ok("as_of is the SCAN's time, never build time", snap1?.snapshot?.as_of === report1.completed_at);

  const row1 = db.prepare("SELECT * FROM scan_report_snapshots WHERE scan_id='scan1'").get();
  ok("D1 row completed with resolver version + assessed_at", row1?.status === "completed" && row1?.resolver_version === CYBER_MOT_RESOLVER_VERSION && row1?.assessed_at === report1.completed_at);
  ok("checksum binds the D1 row to the exact R2 bytes",
     !!row1?.checksum_sha256 && row1.checksum_sha256 === await snapshotSha256Hex(put1.body));

  // ═══ D. Truth consistency ══════════════════════════════════════════════════
  const independent = resolveCyberMotDomainStates(report1, { scanId: "scan1", cyberEssentials: ceSnap1 });
  const same = snap1 && independent.every((d, i) =>
    snap1.domains[i].domain_key === d.domain_key &&
    snap1.domains[i].state === d.state &&
    snap1.domains[i].coverage === d.coverage &&
    JSON.stringify(snap1.domains[i].finding_ids) === JSON.stringify(d.finding_ids));
  ok("snapshot domain states EQUAL the canonical resolver's output at build time", same);
  // Value equality, not mere presence: ws1 HAS a complete questionnaire, so a
  // builder that let answers touch the score would move this number.
  const { resolveAssessmentPresentation } = await import(pathToFileURL(srcPath("engines", "assessment-presentation.js")).href);
  const canonicalAssessment = resolveAssessmentPresentation({ score: report1.cyber_metrics_score, scanQuality: "complete", status: "completed" });
  ok("snapshot Cyber Metrics Score EQUALS the canonical assessment value (questionnaire answers cannot move it)",
     snap1?.overall?.cyber_metrics_score === canonicalAssessment.display_score);
  const brs = deriveScanBusinessRisk(report1);
  ok("BRI internal metrics equal the canonical scan-path derivation",
     snap1?.overall?.business_risk_indicator?.internal_metrics?.score === brs.score &&
     snap1?.overall?.business_risk_indicator?.band === brs.band);

  const ceDomain = snap1?.domains?.find((d) => d.domain_key === "cyber_essentials_readiness");
  ok("CE 2-of-5 contract travels verbatim",
     ceDomain?.cyber_essentials?.assessable_control_count === 2 &&
     ceDomain?.cyber_essentials?.total_control_count === 5 &&
     /based on 2 of 5/.test(ceDomain?.cyber_essentials?.external_coverage_statement ?? ""));
  ok("CE methodology version + revision persisted",
     ceDomain?.cyber_essentials?.readiness_methodology_version === "2026-07-16" &&
     ceDomain?.cyber_essentials?.readiness_methodology_revision === 2);
  ok("per-answer question_set_version travels",
     JSON.stringify(ceDomain?.questionnaire?.question_set_versions) === JSON.stringify(["2026-07-16"]));

  // ═══ Evidence-Grade Law v2 — minimal-viable Item 6 contract ═══════════════
  const EVIDENCE_KEYS = ["basis", "grade", "limits", "repeat_confirmed", "source_type"];
  const validEvidenceAssertion = (assertion) =>
    assertion &&
    JSON.stringify(Object.keys(assertion).sort()) === JSON.stringify(EVIDENCE_KEYS) &&
    EVIDENCE_GRADES.includes(assertion.grade) &&
    EVIDENCE_SOURCE_TYPES.includes(assertion.source_type) &&
    typeof assertion.basis === "string" && assertion.basis.length > 0 &&
    Array.isArray(assertion.limits) && assertion.limits.length > 0 &&
    assertion.limits.every((limit) => typeof limit === "string" && limit.length > 0) &&
    assertion.repeat_confirmed === false;
  const visibleAssertions = [
    snap1?.overall?.assessment_evidence_grade,
    snap1?.overall?.business_risk_indicator?.evidence_grade,
    snap1?.overall?.evidence_grade,
    snap1?.overall?.evidence_completeness?.evidence_grade,
    ...(snap1?.domains || []).flatMap((domain) => [
      domain.evidence_grade,
      domain.cyber_essentials?.evidence_grade,
      domain.questionnaire?.evidence_grade,
    ].filter(Boolean)),
    ...(snap1?.observed_findings || []).map((item) => item.evidence_grade),
    ...(snap1?.observations || []).map((item) => item.evidence_grade),
    ...(snap1?.remediation_actions || []).map((item) => item.evidence_grade),
    ...Object.values(snap1?.monitoring_states?.signals || {}).map((signal) => signal.evidence_grade),
  ];
  ok("every pilot customer-visible assertion carries exactly the five Evidence-Grade fields",
     visibleAssertions.length > 20 && visibleAssertions.every(validEvidenceAssertion));
  ok("Evidence Grade stays separate from detector finding.confidence",
     snap1?.observed_findings?.every((item) =>
       Object.prototype.hasOwnProperty.call(item, "confidence") &&
       item.evidence_grade &&
       !Object.prototype.hasOwnProperty.call(item.evidence_grade, "confidence")));
  ok("repeat_confirmed defaults false everywhere (completion/persistence never implies repeat observation)",
     visibleAssertions.every((assertion) => assertion.repeat_confirmed === false));
  ok("score/band and BRI are explicitly CyberMeters product_policy assertions",
     snap1?.overall?.assessment_evidence_grade?.source_type === "product_policy" &&
     snap1?.overall?.business_risk_indicator?.evidence_grade?.source_type === "product_policy");
  ok("CE full-domain conclusion is L0 and can never render assessed_healthy",
     ceDomain?.state !== "assessed_healthy" &&
     ceDomain?.evidence_grade?.grade === "L0");
  ok("CE named external indicator is separate L1 product_policy over exactly 2 of 5",
     ceDomain?.cyber_essentials?.evidence_grade?.grade === "L1" &&
     ceDomain?.cyber_essentials?.evidence_grade?.source_type === "product_policy" &&
     /2 of 5/.test(ceDomain.cyber_essentials.evidence_grade.basis));
  ok("CE internal questionnaire remains L0 customer_attestation, never scheme conformance",
     ceDomain?.questionnaire?.evidence_grade?.grade === "L0" &&
     ceDomain?.questionnaire?.evidence_grade?.source_type === "customer_attestation");
  const favourableCeSnapshot = composeSnapshot({
    snapshotId: "snap-ce-favourable",
    workspaceId: "ws1",
    domainId: "dom1",
    scanId: "scan-ce-favourable",
    domain: "shared.example",
    report: report1,
    cyberEssentials: {
      has_answers: true,
      complete: true,
      status: "likely_ready",
      top_gaps: [],
    },
    ceReadiness: null,
    caseRows: [],
    questionSetVersions: ["2026-07-16"],
    supersedesSnapshotId: null,
    builtAt: "2026-07-16T12:00:00.000Z",
  });
  const favourableCeDomain = favourableCeSnapshot.domains
    .find((domain) => domain.domain_key === "cyber_essentials_readiness");
  ok("favourable 2-of-5 CE indicator still leaves the full domain evidence-insufficient",
     favourableCeDomain?.state === "evidence_insufficient" &&
     favourableCeDomain?.coverage === "partial" &&
     favourableCeDomain?.evidence_grade?.grade === "L0" &&
     /2 of 5/.test(favourableCeDomain?.state_reason || ""));
  const certDomain = snap1?.domains?.find((d) => d.domain_key === "certificates_trust");
  ok("Certificates & Trust records CT-only scope and never claims the observed cert is live",
     certDomain?.live_certificate_verified === false &&
     /observed Certificate Transparency evidence/.test(certDomain?.state_reason || "") &&
     certDomain?.evidence_grade?.grade === "L1" &&
     certDomain?.evidence_grade?.limits?.some((limit) => /OCSP/.test(limit)));
  const gradeRank = Object.fromEntries(EVIDENCE_GRADES.map((grade, rank) => [grade, rank]));
  const expectedOverallGrade = (snap1?.domains || []).reduce(
    (lowest, domain) =>
      gradeRank[domain.evidence_grade.grade] < gradeRank[lowest]
        ? domain.evidence_grade.grade
        : lowest,
    "L5"
  );
  ok("overall eight-domain Evidence Grade is the minimum constituent-domain grade",
     snap1?.overall?.evidence_grade?.grade === expectedOverallGrade &&
     expectedOverallGrade === "L0");
  ok("score/band and BRI composite grades also use the minimum decisive domain grade",
     snap1?.overall?.assessment_evidence_grade?.grade === expectedOverallGrade &&
     snap1?.overall?.business_risk_indicator?.evidence_grade?.grade === expectedOverallGrade);

  // Questionnaire isolation: the builder may read answers ONLY for their version stamp.
  const builderSrc = fs.readFileSync(srcPath("engines", "report-snapshot.js"), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  const answerReads = builderSrc.match(/cyber_essentials_answers/g) || [];
  ok("builder touches cyber_essentials_answers exactly once, and only for question_set_version",
     answerReads.length === 1 && /SELECT DISTINCT question_set_version FROM cyber_essentials_answers/.test(builderSrc));
  ok("one-score rule: overall carries cyber_metrics_score; BRI exposes band+explanation, numeric only under internal_metrics",
     snap1?.overall?.cyber_metrics_score != null &&
     snap1?.overall?.business_risk_indicator?.band != null &&
     !("score" in (snap1?.overall?.business_risk_indicator ?? {})) &&
     /not a score/i.test(snap1?.overall?.business_risk_indicator?.methodology_disclosure ?? ""));

  // Unknown stays unknown: a partial scan with no evidence must never be healthy.
  seedScan("scan_p", "ws1", "dom1");
  const partialReport = makeReport("scan_p", "dom1", "shared.example", {
    quality: "partial", modules: {}, findings: [], skipped: ["dns", "email_security"], completedAt: "2026-07-16T11:00:00.000Z",
  });
  const resP = await buildScanReportSnapshot(env, {
    workspaceId: "ws1", domainId: "dom1", scanId: "scan_p", domain: "shared.example",
    report: partialReport, cyberEssentials: ceSnap1, assessedAt: partialReport.completed_at,
  });
  const putP = recorded.puts.find((p) => p.key.includes("scan_p"));
  const snapP = putP ? JSON.parse(putP.body) : null;
  ok("partial/absent evidence NEVER resolves assessed_healthy",
     resP.status === "completed" && snapP &&
     snapP.domains.every((d) => d.state !== "assessed_healthy"));
  ok("partial scan is not trend-comparable", snapP?.domains.every((d) => d.trend?.comparable_basis === false));
  ok("missing/degraded evidence lowers the score and overall evidence conclusions",
     snapP?.overall?.assessment_evidence_grade?.grade === "L0" &&
     snapP?.overall?.evidence_grade?.grade === "L0");

  // Domain-local grade isolation: a partial scan caused by the subdomain module
  // must not erase intact Email evidence. Overall remains L0 because Attack
  // Surface lost one of ITS decisive inputs.
  const isolatedPartialReport = makeReport("scan_grade_isolation", "dom1", "shared.example", {
    quality: "partial",
    skipped: ["subdomains"],
    findings: [],
    completedAt: "2026-07-16T11:30:00.000Z",
  });
  isolatedPartialReport.modules.subdomains = {
    count: 0,
    incomplete: true,
    incomplete_reason: "ct_sources_unavailable",
  };
  const isolatedPartialSnapshot = composeSnapshot({
    snapshotId: "snap-grade-isolation",
    workspaceId: "ws1",
    domainId: "dom1",
    scanId: isolatedPartialReport.scan_id,
    domain: "shared.example",
    report: isolatedPartialReport,
    cyberEssentials: ceSnap1,
    ceReadiness: null,
    caseRows: [],
    questionSetVersions: ["2026-07-16"],
    supersedesSnapshotId: null,
    builtAt: "2026-07-16T11:30:01.000Z",
  });
  const isolatedEmail = isolatedPartialSnapshot.domains
    .find((domain) => domain.domain_key === "email_protection");
  const isolatedAttackSurface = isolatedPartialSnapshot.domains
    .find((domain) => domain.domain_key === "attack_surface");
  ok("domain-local grade isolation preserves intact Email evidence on a subdomain-partial scan",
     isolatedEmail?.state === "provisional" &&
     isolatedEmail?.evidence_grade?.grade === "L1");
  ok("domain-local grade isolation still caps the affected Attack Surface domain and overall conclusion",
     isolatedAttackSurface?.evidence_grade?.grade === "L0" &&
     isolatedPartialSnapshot.overall?.evidence_grade?.grade === "L0");

  const resolvedSpfReport = makeReport("scan_spf_l3", "dom1", "shared.example");
  resolvedSpfReport.modules.email_security = {
    spf: {
      present: true,
      resolution_status: "complete",
      resolved_pass_authorisations: ["192.0.2.0/24"],
    },
  };
  resolvedSpfReport.findings = [{
    id: "spf_effective_policy",
    title: "SPF effective-policy observation",
    description: "Resolved PASS-authorisation set retained.",
    severity: "info",
    module: "email_security",
    finding_type: "observation",
    evidence: [{ type: "dns_resolution_chain" }],
  }];
  const resolvedSpfSnapshot = composeSnapshot({
    snapshotId: "snap-spf-l3", workspaceId: "ws1", domainId: "dom1",
    scanId: "scan_spf_l3", domain: "shared.example", report: resolvedSpfReport,
    cyberEssentials: ceSnap1, ceReadiness: null, caseRows: [],
    questionSetVersions: [], supersedesSnapshotId: null,
    builtAt: "2026-07-16T12:00:00.000Z",
  });
  const resolvedSpfFinding = resolvedSpfSnapshot.observations
    .find((finding) => finding.finding_id === "spf_effective_policy");
  const gradedEmailDomain = resolvedSpfSnapshot.domains
    .find((domain) => domain.domain_key === "email_protection");
  ok("signal audit: retained SPF effective-state path can reach L3",
     resolvedSpfFinding?.evidence_grade?.grade === "L3" &&
     /RFC 7208/.test(resolvedSpfFinding.evidence_grade.basis));
  ok("signal audit: Email domain still uses the lowest decisive DNS input, not blanket L3",
     gradedEmailDomain?.evidence_grade?.grade === "L1" &&
     /lowest decisive input/.test(gradedEmailDomain.evidence_grade.basis));

  // ═══ E. Remediation ════════════════════════════════════════════════════════
  const spfAction = snap1?.remediation_actions?.find((a) => a.finding_ids.includes("email_missing_spf"));
  ok("actions resolve through the canonical registry (title + action present)",
     !!spfAction && !!spfAction.title && !!spfAction.action && !!spfAction.remediation_id);
  ok("automated support carries the observation ceiling, case linkage + ownership fields",
     spfAction?.verification_support === "automated" &&
     spfAction?.verification_ceiling === verificationCeiling("automated") &&
     spfAction?.case_id === "mc1");
  // verification_support travels on the ITEMS too (the binding vocabulary-doc rule),
  // by value, and the per-domain distribution reflects it.
  const spfItem = snap1?.observed_findings?.find((i) => i.finding_id === "email_missing_spf");
  ok("observed-finding items carry verification_method + support by VALUE",
     spfItem?.verification_method === "dns_recheck" &&
     spfItem?.verification_support === "automated" &&
     spfItem?.managed_case_id === "mc1");
  ok("per-domain verification_support_distribution reflects the items",
     snap1?.domains?.find((d) => d.domain_key === "email_protection")?.verification_support_distribution?.includes("automated"));
  ok("unknown finding types fail CLOSED into unmapped_finding_types (no invented copy)",
     snap1?.unmapped_finding_types?.includes("zz_unknown_finding") &&
     !snap1?.remediation_actions?.some((a) => a.finding_ids.includes("zz_unknown_finding")));
  ok("observation taxonomy preserved (info items are observations, not Observed Findings)",
     snap1?.observations?.some((i) => i.finding_id === "tls_ciphers_info") &&
     !snap1?.observed_findings?.some((i) => i.finding_id === "tls_ciphers_info"));
  ok("snapshot key vocabulary: 'observed_findings', never 'verified_findings'",
     snap1 && ("observed_findings" in snap1) && !("verified_findings" in snap1));

  // One remediation ← many findings: two SPF-class findings resolve to one action.
  seedScan("scan_m", "ws1", "dom1");
  const multiReport = makeReport("scan_m", "dom1", "shared.example", {
    completedAt: "2026-07-16T11:10:00.000Z",
    findings: [
      { id: "email_missing_spf", title: "SPF record missing", description: "d", severity: "high", module: "email_security", finding_type: "finding", evidence: [] },
      { id: "email_no_spf", title: "SPF record missing (legacy alias)", description: "d", severity: "medium", module: "email_security", finding_type: "finding", evidence: [] },
    ],
  });
  await buildScanReportSnapshot(env, {
    workspaceId: "ws1", domainId: "dom1", scanId: "scan_m", domain: "shared.example",
    report: multiReport, cyberEssentials: ceSnap1, assessedAt: multiReport.completed_at,
  });
  const snapM = JSON.parse(recorded.puts.find((p) => p.key.includes("scan_m")).body);
  const spfActions = snapM.remediation_actions.filter((a) => a.remediation_id === "email.spf.publish");
  ok("one root remediation references multiple findings (no duplicated pressure)",
     spfActions.length === 1 && spfActions[0].finding_ids.length === 2);

  // ═══ B. Immutability + supersession ════════════════════════════════════════
  const putsBefore = recorded.puts.filter((p) => p.key.includes("/scan1/")).length;
  // The world changes AFTER completion — a rebuild must NOT re-render history.
  db.prepare("UPDATE managed_cases SET status='closed' WHERE id='mc1'").run();
  const res1b = await buildScanReportSnapshot(env, {
    workspaceId: "ws1", domainId: "dom1", scanId: "scan1", domain: "shared.example",
    report: report1, cyberEssentials: ceSnap1, assessedAt: report1.completed_at,
  });
  ok("rebuild of a completed scan is an idempotent no-op returning the canonical snapshot",
     res1b.status === "exists" && res1b.snapshot_id === res1.snapshot_id);
  ok("no second R2 write for the same scan",
     recorded.puts.filter((p) => p.key.includes("/scan1/")).length === putsBefore);
  const row1b = db.prepare("SELECT * FROM scan_report_snapshots WHERE scan_id='scan1'").get();
  ok("completed row is byte-identical after the rebuild attempt",
     row1b.checksum_sha256 === row1.checksum_sha256 && row1b.completed_at === row1.completed_at);

  // Later scan supersedes append-only.
  const laterRow = db.prepare("SELECT * FROM scan_report_snapshots WHERE scan_id='scan_p'").get();
  ok("a later completed Cyber MOT records supersedes_snapshot_id at creation",
     laterRow?.supersedes_snapshot_id === res1.snapshot_id);
  ok("the superseded historical row itself is UNCHANGED (append-only supersession)",
     db.prepare("SELECT checksum_sha256 FROM scan_report_snapshots WHERE id=?").get(res1.snapshot_id).checksum_sha256 === row1.checksum_sha256);

  // Read path never recalculates: the snapshot route applies only the canonical
  // fail-closed customer projection over immutable R2 bytes.
  const routeSrc = fs.readFileSync(srcPath("routes", "scans.js"), "utf8");
  const snapRouteBlock = routeSrc.slice(routeSrc.indexOf("GET /api/scans/:id/snapshot"), routeSrc.indexOf("GET /api/scans/:id/report "));
  ok("snapshot read route exists and never re-resolves/re-scores/re-remediates",
     snapRouteBlock.length > 200 &&
     !/resolveCyberMotDomainStates|deriveScanBusinessRisk|findingRemediation|buildCyberEssentials/.test(snapRouteBlock));

  // ═══ C. Concurrency / partial failure ═══════════════════════════════════════
  seedScan("scan_c", "ws1", "dom1");
  const cReport = makeReport("scan_c", "dom1", "shared.example", { completedAt: "2026-07-16T11:20:00.000Z" });
  const [c1, c2] = await Promise.all([
    buildScanReportSnapshot(env, { workspaceId: "ws1", domainId: "dom1", scanId: "scan_c", domain: "shared.example", report: cReport, cyberEssentials: ceSnap1, assessedAt: cReport.completed_at }),
    buildScanReportSnapshot(env, { workspaceId: "ws1", domainId: "dom1", scanId: "scan_c", domain: "shared.example", report: cReport, cyberEssentials: ceSnap1, assessedAt: cReport.completed_at }),
  ]);
  const cRows = db.prepare("SELECT status FROM scan_report_snapshots WHERE scan_id='scan_c'").all();
  ok("two concurrent builders cannot both become canonical",
     cRows.filter((r) => r.status === "completed").length === 1 &&
     [c1, c2].filter((r) => r.status === "completed").length === 1 &&
     [c1, c2].filter((r) => r.status === "exists" || r.status === "in_progress").length === 1);

  // R2 down: the D1 row must never claim completion.
  seedScan("scan_f", "ws1", "dom1");
  const fReport = makeReport("scan_f", "dom1", "shared.example", { completedAt: "2026-07-16T11:30:00.000Z" });
  flags.r2Fail = true;
  const rf = await buildScanReportSnapshot(env, { workspaceId: "ws1", domainId: "dom1", scanId: "scan_f", domain: "shared.example", report: fReport, cyberEssentials: ceSnap1, assessedAt: fReport.completed_at });
  flags.r2Fail = false;
  ok("failed R2 write → visible 'failed' row, NEVER a completed claim",
     rf.status === "failed" &&
     db.prepare("SELECT COUNT(*) c FROM scan_report_snapshots WHERE scan_id='scan_f' AND status='completed'").get().c === 0 &&
     db.prepare("SELECT COUNT(*) c FROM scan_report_snapshots WHERE scan_id='scan_f' AND status='failed'").get().c === 1);
  const rf2 = await buildScanReportSnapshot(env, { workspaceId: "ws1", domainId: "dom1", scanId: "scan_f", domain: "shared.example", report: fReport, cyberEssentials: ceSnap1, assessedAt: fReport.completed_at });
  ok("persistence failures are retryable — the retry completes exactly once",
     rf2.status === "completed" &&
     db.prepare("SELECT COUNT(*) c FROM scan_report_snapshots WHERE scan_id='scan_f' AND status='completed'").get().c === 1);

  // D1 finalize down after a durable R2 write: still no completed claim.
  seedScan("scan_g", "ws1", "dom1");
  const gReport = makeReport("scan_g", "dom1", "shared.example", { completedAt: "2026-07-16T11:40:00.000Z" });
  flags.d1FinalizeFail = true;
  const rg = await buildScanReportSnapshot(env, { workspaceId: "ws1", domainId: "dom1", scanId: "scan_g", domain: "shared.example", report: gReport, cyberEssentials: ceSnap1, assessedAt: gReport.completed_at });
  flags.d1FinalizeFail = false;
  ok("failed D1 finalisation cannot expose an orphan as canonical",
     rg.status === "failed" &&
     db.prepare("SELECT COUNT(*) c FROM scan_report_snapshots WHERE scan_id='scan_g' AND status='completed'").get().c === 0 &&
     db.prepare("SELECT COUNT(*) c FROM scan_report_snapshots WHERE scan_id='scan_g' AND status='failed'").get().c === 1);

  // Stale crashed claim is reclaimed, then a fresh build succeeds.
  seedScan("scan_s", "ws1", "dom1");
  db.prepare(`INSERT INTO scan_report_snapshots (id, workspace_id, domain_id, scan_id, status, r2_key, snapshot_schema_version, resolver_version, assessed_at, created_at)
              VALUES ('snap-stale','ws1','dom1','scan_s','building','reports/snapshots/ws1/scan_s/snap-stale.json','1',?, '2026-07-16T11:50:00.000Z', datetime('now','-40 minutes'))`)
    .run(CYBER_MOT_RESOLVER_VERSION);
  const sReport = makeReport("scan_s", "dom1", "shared.example", { completedAt: "2026-07-16T11:50:00.000Z" });
  const rs = await buildScanReportSnapshot(env, { workspaceId: "ws1", domainId: "dom1", scanId: "scan_s", domain: "shared.example", report: sReport, cyberEssentials: ceSnap1, assessedAt: sReport.completed_at });
  ok("a stale crashed claim is reclaimed as failed and the retry completes",
     rs.status === "completed" &&
     db.prepare("SELECT status FROM scan_report_snapshots WHERE id='snap-stale'").get().status === "failed");

  // ═══ G. Tenant + soft-delete + purge ════════════════════════════════════════
  seedScan("scan_ws2", "ws2", "dom2");
  const report2 = makeReport("scan_ws2", "dom2", "shared.example", { completedAt: "2026-07-16T12:00:00.000Z" });
  store.set("reports/scan_ws2.json", JSON.stringify(report2));
  const r2res = await buildScanReportSnapshot(env, { workspaceId: "ws2", domainId: "dom2", scanId: "scan_ws2", domain: "shared.example", report: report2, cyberEssentials: await ceSnapFor("ws2"), assessedAt: report2.completed_at });
  ok("the SAME hostname in two tenants yields two independent snapshots", r2res.status === "completed");
  ok("workspace-scoped history reads cannot cross tenants",
     db.prepare("SELECT COUNT(*) c FROM scan_report_snapshots WHERE workspace_id='ws1' AND scan_id='scan_ws2'").get().c === 0 &&
     db.prepare("SELECT COUNT(*) c FROM scan_report_snapshots WHERE workspace_id='ws2'").get().c === 1);
  // The supersession chain must never cross tenants: ws1 holds completed
  // snapshots for the SAME hostname, so a hostname-based (or unscoped) previous-
  // lookup would have linked ws2's first snapshot to ws1's history.
  ok("supersession never crosses tenants (same hostname, independent chains)",
     db.prepare("SELECT supersedes_snapshot_id s FROM scan_report_snapshots WHERE scan_id='scan_ws2'").get().s === null);
  ok("snapshot R2 keys are tenant-prefixed (cannot collide across tenants)",
     recorded.puts.filter((p) => p.key.startsWith("reports/snapshots/")).length > 0 &&
     recorded.puts.filter((p) => p.key.startsWith("reports/snapshots/")).every((p) =>
       p.key.startsWith("reports/snapshots/ws1/") || p.key.startsWith("reports/snapshots/ws2/") || p.key.startsWith("reports/snapshots/wsE2E/")));

  const rDead = await buildScanReportSnapshot(env, { workspaceId: "wsDead", domainId: "dom1", scanId: "scan_dead", domain: "shared.example", report: makeReport("scan_dead", "dom1", "shared.example"), cyberEssentials: null, assessedAt: "2026-07-16T12:10:00.000Z" });
  ok("a soft-deleted workspace receives NO snapshot (fail-closed writer guard)",
     rDead.status === "skipped" && rDead.reason === "workspace_inactive" &&
     db.prepare("SELECT COUNT(*) c FROM scan_report_snapshots WHERE workspace_id='wsDead'").get().c === 0);

  // ═══ Production wiring — the REAL scan-finalize path builds the snapshot ════
  // Walks the genuine customer path (the guard-arity lesson: a seeded end state
  // proves nothing). runScanEngine runs with network disabled: modules fail
  // honestly, the scan still finalizes, and Phase 8o must produce a completed
  // snapshot whose per-domain states EQUAL the 091 rows the same pass persisted.
  {
    db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsE2E','u1','E2E')").run();
    db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('domE','u1','e2e.example')").run();
    db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('wsE2E','domE')").run();
    db.prepare("INSERT INTO scans (id, workspace_id, domain_id, domain, status, created_at) VALUES ('scanE2E','wsE2E','domE','e2e.example','running',datetime('now'))").run();
    const { runScanEngine } = await import(pathToFileURL(srcPath("engines", "scan-engine.js")).href);
    await runScanEngine("scanE2E", "domE", "wsE2E", "e2e.example", env, {});
    const eRow = db.prepare("SELECT * FROM scan_report_snapshots WHERE scan_id='scanE2E'").get();
    ok("scan finalize (Phase 8o) builds a completed snapshot through the REAL path",
       eRow?.status === "completed" && eRow?.resolver_version === CYBER_MOT_RESOLVER_VERSION);
    const eBody = eRow ? store.get(eRow.r2_key) : null;
    const eSnap = eBody ? JSON.parse(eBody) : null;
    const e091 = db.prepare("SELECT domain_key, state FROM cyber_mot_domain_states WHERE scan_id='scanE2E' ORDER BY domain_key").all();
    ok("snapshot domains EQUAL the 091 state rows persisted by the same pass (one resolver, one CE snapshot)",
       !!eSnap && e091.length === 8 && e091.every((r) =>
         eSnap.domains.find((d) => d.domain_key === r.domain_key)?.state === r.state));
    ok("network-disabled scan is honest in the snapshot too (nothing assessed_healthy)",
       !!eSnap && eSnap.domains.every((d) => d.state !== "assessed_healthy"));
  }

  // ═══ Read-route contract — the REAL worker fetch handler ════════════════════
  {
    const pw = await hashPassword("Sup3r-secret-pw");
    db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified, mfa_enabled) VALUES ('u2','m@a.co',?, 'M','free','active',1,0)").run(pw);
    db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('m1','ws1','u2','admin')").run();
    db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('m2','ws2','u2','admin')").run();
    db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES ('sess1','u2',?,datetime('now','+1 day'))").run(await hashToken("raw-m5c-token"));
    const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
    const call = async (method, pathname) => {
      const res = await worker.fetch(new Request("https://api.cybermeters.com" + pathname, {
        method, headers: { Authorization: "Bearer raw-m5c-token" },
      }), env, ctx);
      const text = await res.text();
      let data = null; try { data = JSON.parse(text); } catch { /* non-JSON */ }
      return { status: res.status, data, text };
    };

    const got = await call("GET", "/api/scans/scan1/snapshot");
    const { projectPhase5SnapshotForCustomer } = await import(
      pathToFileURL(srcPath("engines", "phase5-evidence.js")).href
    );
    const expectedCustomerSnapshot = projectPhase5SnapshotForCustomer(
      JSON.parse(put1.body),
      report1.modules,
    );
    ok("route serves the fail-closed customer projection while immutable R2 bytes remain verbatim",
       got.status === 200
       && store.get(put1.key) === put1.body
       && JSON.stringify(got.data?.snapshot) === JSON.stringify(JSON.parse(put1.body))
       && JSON.stringify(got.data?.customer_snapshot) === JSON.stringify(expectedCustomerSnapshot)
       && got.data?.customer_projection_metadata?.checksum_scope === "immutable_snapshot"
       && got.data?.customer_projection_metadata?.customer_projection_applied === true
       && got.data?.customer_projection_metadata?.authoritative_customer_field === "customer_snapshot");
    ok("route derives superseded_by from the append-only chain",
       got.data?.superseded_by?.snapshot_id === laterRow?.id &&
       got.data?.integrity?.verified === true);

    // A 'building' row must never be served — the D1 status gate, not R2 existence.
    seedScan("scan_b", "ws1", "dom1");
    db.prepare(`INSERT INTO scan_report_snapshots (id, workspace_id, domain_id, scan_id, status, r2_key, snapshot_schema_version, resolver_version, assessed_at)
                VALUES ('snap-bld','ws1','dom1','scan_b','building','reports/snapshots/ws1/scan_b/snap-bld.json','1',?, '2026-07-16T13:00:00.000Z')`).run(CYBER_MOT_RESOLVER_VERSION);
    const bld = await call("GET", "/api/scans/scan_b/snapshot");
    ok("a building snapshot is 409, never served", bld.status === 409);

    seedScan("scan_none", "ws1", "dom1");
    ok("a scan with no snapshot is an honest 404", (await call("GET", "/api/scans/scan_none/snapshot")).status === 404);

    // Integrity: corrupt the stored bytes → the checksum gate must refuse to serve.
    const scanMRow = db.prepare("SELECT r2_key FROM scan_report_snapshots WHERE scan_id='scan_m'").get();
    const goodBytes = store.get(scanMRow.r2_key);
    store.set(scanMRow.r2_key, goodBytes + " ");
    const corrupt = await call("GET", "/api/scans/scan_m/snapshot");
    ok("corrupted snapshot bytes are refused (500), never served as truth",
       corrupt.status === 500 && !String(corrupt.text).includes("remediation_actions"));
    ok("integrity failure is customer-safe (no stack, no checksum internals)",
       !/at\s+\w+|checksum mismatch/i.test(String(corrupt.text)));
    store.set(scanMRow.r2_key, goodBytes);

    // ── Repair-on-read: the recovery half of the claim pattern is ALIVE ─────
    // A transient failure leaves only 'failed' rows; its one remaining bounded
    // retry is customer-authorised through scan detail, never spent by a passive
    // snapshot reader. A killed Worker leaves 'building' forever and the
    // canonical stale-claim recovery still repairs it. A scan with NO attempt
    // stays honestly 404 — no backfill.
    seedScan("scan_r", "ws1", "dom1");
    const reportR = makeReport("scan_r", "dom1", "shared.example", { completedAt: "2026-07-16T14:00:00.000Z" });
    store.set("reports/scan_r.json", JSON.stringify(reportR));
    db.prepare(`INSERT INTO scan_report_snapshots (id, workspace_id, domain_id, scan_id, status, r2_key, snapshot_schema_version, resolver_version, assessed_at, metadata_json)
                VALUES ('snap-fail-r','ws1','dom1','scan_r','failed','reports/snapshots/ws1/scan_r/snap-fail-r.json','1',?, '2026-07-16T14:00:00.000Z','{"failure_reason":"injected"}')`).run(CYBER_MOT_RESOLVER_VERSION);
    const failedRowsBeforePassiveRead = db.prepare(
      "SELECT COUNT(*) c FROM scan_report_snapshots WHERE scan_id='scan_r'"
    ).get().c;
    const passiveFailedRead = await call("GET", "/api/scans/scan_r/snapshot");
    ok("a passive snapshot read preserves failed state and the customer retry right",
       passiveFailedRead.status === 500 &&
       passiveFailedRead.data?.code === "report_generation_failed" &&
       passiveFailedRead.data?.report_availability?.status === "report_unavailable" &&
       db.prepare("SELECT COUNT(*) c FROM scan_report_snapshots WHERE scan_id='scan_r'").get().c ===
         failedRowsBeforePassiveRead);
    const explicitRepair = await call("GET", "/api/scans/scan_r?retry_report=1");
    const repaired = await call("GET", "/api/scans/scan_r/snapshot");
    ok("explicit scan-detail customer retry repairs once, then passive snapshot serves it",
       explicitRepair.status === 200 &&
       explicitRepair.data?.report_availability?.status === "report_ready" &&
       repaired.status === 200 &&
       repaired.data?.snapshot?.snapshot?.scan_id === "scan_r");

    seedScan("scan_t", "ws1", "dom1");
    const reportT = makeReport("scan_t", "dom1", "shared.example", { completedAt: "2026-07-16T14:10:00.000Z" });
    store.set("reports/scan_t.json", JSON.stringify(reportT));
    db.prepare(`INSERT INTO scan_report_snapshots (id, workspace_id, domain_id, scan_id, status, r2_key, snapshot_schema_version, resolver_version, assessed_at, created_at)
                VALUES ('snap-stuck','ws1','dom1','scan_t','building','reports/snapshots/ws1/scan_t/snap-stuck.json','1',?, '2026-07-16T14:10:00.000Z', datetime('now','-40 minutes'))`).run(CYBER_MOT_RESOLVER_VERSION);
    const unstuck = await call("GET", "/api/scans/scan_t/snapshot");
    ok("a stale crashed 'building' attempt is repaired on read (never a permanent 409)",
       unstuck.status === 200 &&
       db.prepare("SELECT status FROM scan_report_snapshots WHERE id='snap-stuck'").get().status === "failed");

    ok("a scan with NO attempt is NOT backfilled by the read path (honest 404)",
       (await call("GET", "/api/scans/scan_none/snapshot")).status === 404 &&
       db.prepare("SELECT COUNT(*) c FROM scan_report_snapshots WHERE scan_id='scan_none'").get().c === 0);

    // Member-side tenant scoping: a member of BOTH workspaces listing ws2 must
    // see ONLY ws2 rows — this exercises the SQL's own WHERE, not the role gate.
    const list2 = await call("GET", "/api/workspaces/ws2/report-snapshots");
    ok("workspace history list is scoped by the SQL itself (no ws1 rows in a ws2 list)",
       list2.status === 200 &&
       (list2.data?.snapshots ?? []).length === 1 &&
       list2.data.snapshots.every((s) => s.workspace_id === "ws2") &&
       list2.data.snapshots[0].superseded_by === null);
  }

  // Purge: R2 objects deleted with their pointer rows; the other tenant intact.
  const ws1Keys = db.prepare("SELECT r2_key FROM scan_report_snapshots WHERE workspace_id='ws1' AND status='completed'").all().map((r) => r.r2_key);
  ok("ws1 holds completed snapshots to purge (purge test is not vacuous)", ws1Keys.length >= 3);
  let guard = 0, pres;
  do { pres = await purgeWorkspaceData(env, "ws1"); } while (pres && pres.done === false && ++guard < 80);
  ok("purge reached completion", pres?.done === true);
  ok("purge removed every ws1 snapshot row",
     db.prepare("SELECT COUNT(*) c FROM scan_report_snapshots WHERE workspace_id='ws1'").get().c === 0);
  ok("purge deleted every ws1 snapshot R2 object (R2 before pointer rows)",
     ws1Keys.every((k) => recorded.deletes.includes(k)));
  ok("the other tenant's snapshot survives the purge",
     db.prepare("SELECT COUNT(*) c FROM scan_report_snapshots WHERE workspace_id='ws2' AND status='completed'").get().c === 1 &&
     !recorded.deletes.some((k) => k.startsWith("reports/snapshots/ws2/")));

  // ═══ H. Vocabulary ══════════════════════════════════════════════════════════
  ok("manual/external/unsupported ceilings never claim Verified/Confirmed",
     ["manual", "external", "unsupported", "garbage-value", null].every(
       (s) => s === "automated" || !/verified|confirmed/i.test(verificationCeiling(s))));
  ok("unrecognised support values fail CLOSED to the weakest ceiling",
     verificationCeiling("something_new") === verificationCeiling("unsupported"));
  const wholeBlob = put1.body;
  ok("snapshot never claims certification / a pass / compliance",
     !/certified|certification granted|compliant with Cyber Essentials|passed Cyber Essentials/i.test(wholeBlob));

  // A manual-attestation finding COMPOSED into a snapshot: the item and the
  // action must carry manual support and the attested ceiling — proving the
  // composer routes non-automated supports through verificationCeiling rather
  // than only the unit function being correct.
  {
    const manualType = listRegisteredFindingTypes().find(
      (t) => resolveRemediation({ finding_type: t })?.verification_method === "manual_attestation");
    ok("registry exposes at least one manual_attestation finding type (test is not vacuous)", !!manualType);
    if (manualType) {
      const manSnap = composeSnapshot({
        snapshotId: "snap-man", workspaceId: "wsX", domainId: "domX", scanId: "scanMan",
        domain: "man.example",
        report: makeReport("scanMan", "domX", "man.example", {
          findings: [{ id: manualType, title: "Manual condition", description: "d", severity: "medium", module: "email_security", finding_type: "finding", evidence: [] }],
        }),
        cyberEssentials: null, ceReadiness: null, caseRows: [], questionSetVersions: [],
        supersedesSnapshotId: null, builtAt: "2026-07-16T12:00:00.000Z",
      });
      const manItem = manSnap.observed_findings.find((i) => i.finding_id === manualType);
      const manAction = manSnap.remediation_actions.find((a) => a.finding_ids.includes(manualType));
      ok("a manual-attestation finding composes with support 'manual' end to end",
         manItem?.verification_support === "manual" && manAction?.verification_support === "manual");
      ok("the composed attestation ceiling never claims Verified/Confirmed",
         !!manAction?.verification_ceiling &&
         /attested by customer/i.test(manAction.verification_ceiling) &&
         !/verified|confirmed/i.test(manAction.verification_ceiling));
    }
  }

  // composeSnapshot purity: same inputs → identical bytes (reproducibility).
  const pureArgs = {
    snapshotId: "snap-pure", workspaceId: "wsX", domainId: "domX", scanId: "scanX",
    domain: "pure.example", report: makeReport("scanX", "domX", "pure.example"),
    cyberEssentials: null, ceReadiness: null, caseRows: [], questionSetVersions: [],
    supersedesSnapshotId: null, builtAt: "2026-07-16T12:00:00.000Z",
  };
  ok("composeSnapshot is deterministic (same inputs → identical JSON)",
     JSON.stringify(composeSnapshot(pureArgs)) === JSON.stringify(composeSnapshot(pureArgs)));

  // ── Report ──────────────────────────────────────────────────────────────────
  console.log(`\nM5.c reporting snapshot: ${pass}/${pass + fail} passed`);
  if (fail) { console.error("m5c-reporting-snapshot validation FAILED"); process.exit(1); }

  // ═══ Mutation stage — each guard must CATCH its reintroduced defect ═════════
  if (!process.argv.includes("--no-mutate")) {
    const MUTATIONS = [
      {
        name: "ninth Admin Exposure domain added",
        file: srcPath("engines", "report-snapshot.js"),
        from: "    domains: domainEntries,",
        to:   "    domains: [...domainEntries, { domain_key: \"admin_exposure\", state: \"assessed_healthy\", trend: {} }],",
      },
      {
        name: "one of the eight domains dropped",
        file: srcPath("engines", "report-snapshot.js"),
        from: "    domains: domainEntries,",
        to:   "    domains: domainEntries.slice(0, 7),",
      },
      {
        name: "five-pillar intelligence_engines section restored",
        file: srcPath("engines", "report-snapshot.js"),
        from: "    domains: domainEntries,",
        to:   "    intelligence_engines: { attack_surface: {}, business_email: {}, identity: {}, brand: {}, executive: {} },\n    domains: domainEntries,",
      },
      {
        name: "completed snapshot overwritten on rebuild (INSERT OR REPLACE)",
        file: srcPath("engines", "report-snapshot.js"),
        from: "      `INSERT OR IGNORE INTO scan_report_snapshots",
        to:   "      `INSERT OR REPLACE INTO scan_report_snapshots",
      },
      {
        name: "completed claimed BEFORE the R2 write is durable",
        file: srcPath("engines", "report-snapshot.js"),
        from: "    // R2 first — 'completed' is only ever claimed over a durable object.\n    await env.cybermeters_reports.put(r2Key, body, {",
        to:   "    await env.cybermeters_db.prepare(`UPDATE scan_report_snapshots SET status = 'completed', checksum_sha256 = ?, size_bytes = ?, completed_at = ? WHERE id = ? AND status = 'building'`).bind(checksum, body.length, new Date().toISOString(), snapshotId).run();\n    await env.cybermeters_reports.put(r2Key, body, {",
      },
      {
        name: "unmapped finding types silently dropped (fail-open)",
        file: srcPath("engines", "report-snapshot.js"),
        from: "    if (!rem && f.finding_type !== \"observation\" && f.id) unmappedTypes.add(f.id);",
        to:   "    if (false) unmappedTypes.add(f.id);",
      },
      {
        name: "questionnaire answers leak into the Cyber Metrics Score",
        file: srcPath("engines", "report-snapshot.js"),
        from: "      cyber_metrics_score: assessment.display_score,",
        to:   "      cyber_metrics_score: (questionSetVersions.length ? 100 : assessment.display_score),",
      },
      {
        name: "customer-visible finding loses its Evidence-Grade assertion",
        file: srcPath("engines", "report-snapshot.js"),
        from: "      evidence_grade: findingEvidenceGrade(f, report),",
        to:   "      evidence_grade: null,",
      },
      {
        name: "overall eight-domain grade hides the lowest constituent domain",
        file: srcPath("engines", "report-snapshot.js"),
        from: "    grade: lowestEvidenceGrade(domainEntries.map((entry) => entry.evidence_grade)),",
        to:   "    grade: \"L5\",",
      },
      {
        name: "score and BRI composite grades hide the lowest constituent domain",
        file: srcPath("engines", "report-snapshot.js"),
        from: "  let grade = lowestEvidenceGrade(domainEntries.map((entry) => entry.evidence_grade));",
        to:   "  let grade = \"L5\";",
      },
      {
        name: "completed scan is mistaken for repeat-confirmed evidence",
        file: srcPath("engines", "report-snapshot.js"),
        from: "    repeat_confirmed: repeat_confirmed === true,",
        to:   "    repeat_confirmed: true,",
      },
      {
        name: "Cyber Essentials full-domain conclusion promoted back to healthy",
        file: srcPath("engines", "cyber-mot-domains.js"),
        from: "          base.state = CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT;\n          base.coverage = provisional ? quality : \"partial\";",
        to:   "          base.state = CYBER_MOT_STATES.ASSESSED_HEALTHY;\n          base.coverage = provisional ? quality : \"complete\";",
      },
      {
        name: "unrelated partial module globally caps every domain Evidence Grade",
        file: srcPath("engines", "report-snapshot.js"),
        from: "  if (intrinsicallyInsufficientState || ownRequiredEvidenceIncomplete || monitoringIncomplete) {",
        to:   "  if (entry?.coverage !== \"complete\" || intrinsicallyInsufficientState || ownRequiredEvidenceIncomplete || monitoringIncomplete) {",
      },
      {
        name: "CT observation relabelled as a live certificate verification",
        file: srcPath("engines", "report-snapshot.js"),
        from: "      entry.live_certificate_verified = false;",
        to:   "      entry.live_certificate_verified = true;",
      },
      {
        name: "score/band dressed as normative protocol rather than product policy",
        file: srcPath("engines", "report-snapshot.js"),
        from: "    source_type: \"product_policy\",\n    basis: `${label} applies CyberMeters methodology",
        to:   "    source_type: \"normative_protocol\",\n    basis: `${label} applies CyberMeters methodology",
      },
      {
        name: "customer attestation relabelled as Verified",
        file: srcPath("engines", "report-snapshot.js"),
        from: "      return \"Attested by customer — not externally verifiable.\";",
        to:   "      return \"Verified by customer attestation.\";",
      },
      {
        name: "insufficient evidence promoted to healthy (resolver second-guessed)",
        file: srcPath("engines", "report-snapshot.js"),
        from: "  const domains = resolveCyberMotDomainStates(reportForCustomer, { scanId, cyberEssentials });",
        to:   "  const domains = resolveCyberMotDomainStates(reportForCustomer, { scanId, cyberEssentials }).map((d) => (d.state === \"evidence_insufficient\" || d.state === \"provisional\" || d.state === \"not_yet_assessed\" ? { ...d, state: \"assessed_healthy\" } : d));",
      },
      {
        name: "methodology stamp dropped from the snapshot",
        file: srcPath("engines", "report-snapshot.js"),
        from: "      cyber_mot_resolver_version: CYBER_MOT_RESOLVER_VERSION,",
        to:   "      cyber_mot_resolver_version: null,",
      },
      {
        name: "current Cyber Essentials question-set stamp dropped from the snapshot",
        file: srcPath("engines", "report-snapshot.js"),
        from: "      ce_question_set_version: CE_QUESTION_SET_VERSION,",
        to:   "      ce_question_set_version: null,",
      },
      {
        name: "supersession chain severed",
        file: srcPath("engines", "report-snapshot.js"),
        from: "  const supersedesSnapshotId = previous?.id ?? null;",
        to:   "  const supersedesSnapshotId = null;",
      },
      {
        name: "purge stops deleting snapshot R2 objects (#106 class)",
        file: srcPath("index.js"),
        // F-009 re-anchor: the raw `.delete(...).catch(() => {})` was replaced by
        // deleteR2ObjectVerified, which deletes AND proves absence before the
        // pointer row is removed. Same mutation intent — drop the R2 delete —
        // against the current call site. This validator correctly reported
        // "the mutation tests nothing" when the old anchor disappeared.
        from: "      await deleteR2ObjectVerified(env, s.r2_key);",
        to:   "      // R2 delete dropped",
      },
      {
        name: "snapshot read route re-derives domain states (renderer brain returns)",
        file: srcPath("routes", "scans.js"),
        from: "          customer_snapshot: customerSnapshot,",
        to:   "          customer_snapshot: { ...customerSnapshot, domains: (customerSnapshot.domains || []).map((domain) => ({ ...domain, state: 'assessed_healthy' })) },",
      },
      {
        name: "Phase 8o wiring deleted — scan finalize stops building the snapshot",
        file: srcPath("engines", "scan-engine.js"),
        from: "        await buildScanReportSnapshot(env, {",
        to:   "        if (false) await buildScanReportSnapshot(env, {",
      },
      {
        name: "checksum verification dropped from the shared read helper",
        file: srcPath("engines", "report-snapshot.js"),
        from: "  if (row.checksum_sha256 && checksum !== row.checksum_sha256) {",
        to:   "  if (false) {",
      },
      {
        name: "building-status gate dropped — half-written snapshots served",
        file: srcPath("engines", "report-snapshot.js"),
        from: "  if (row.status !== \"completed\") return { status: \"building\", row, reason: \"build_in_progress\" };",
        to:   "  if (false) return { status: \"building\", row, reason: \"build_in_progress\" };",
      },
      {
        name: "workspace history list loses its tenant WHERE (role gate alone left standing)",
        file: srcPath("routes", "workspace-reports.js"),
        from: "                   FROM scan_report_snapshots s\n                   WHERE s.workspace_id = ?",
        to:   "                   FROM scan_report_snapshots s\n                   WHERE (s.workspace_id = ? OR 1=1)",
      },
    ];
    let mfail = 0;
    for (const m of MUTATIONS) {
      const original = fs.readFileSync(m.file, "utf8");
      if (!original.includes(m.from)) {
        console.log(`FAIL mutation anchor missing: ${m.name} — the mutation tests nothing`);
        mfail++; continue;
      }
      fs.writeFileSync(m.file, original.replace(m.from, m.to));
      let survived = true;
      try { execFileSync(process.execPath, [self, "--no-mutate"], { stdio: "pipe" }); }
      catch { survived = false; }
      finally { fs.writeFileSync(m.file, original); }
      if (survived) { console.log(`FAIL mutation NOT caught: ${m.name} — the suite stayed green, so the guard proves nothing`); mfail++; }
      else { console.log(`  mutation CAUGHT: ${m.name}`); }
    }
    if (mfail) { console.error("m5c-reporting-snapshot mutation validation FAILED"); process.exit(1); }
  }

  console.log("m5c-reporting-snapshot validation passed");
}

main().catch((e) => { console.error("m5c-reporting-snapshot runner crashed:", e); process.exit(1); });
