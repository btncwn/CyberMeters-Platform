#!/usr/bin/env node
//
// M5.d — Renderer migration to the canonical snapshot.
//
// Locks out: renderers regrowing calculation brains; live-table changes
// rewriting rendered history; score/band/BRI divergence across surfaces;
// five-pillar or Vendor Risk/Supply Chain output returning; vocabulary
// upgrades ("Verified" for attestation); unknown snapshot schema misrendered;
// reconstruction injecting current workspace state into historical snapshots;
// renderer failure mutating the immutable snapshot.
//
// Drives the REAL worker fetch over real schema+migrations (m5c harness) and
// ends with source mutations proven caught (--no-mutate skips in the child).
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

// D1 stub with a WRITE LOG so renders can be proven side-effect-free.
function makeD1(db, writeLog) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run:   async () => {
      if (/^\s*(insert|update|delete)/i.test(sql) && /scan_report_snapshots/i.test(sql)) writeLog.push(sql.slice(0, 80));
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

function makeR2(store, recorded) {
  return {
    get: async (key) => {
      const body = store.get(key);
      if (body == null) return null;
      return { json: async () => JSON.parse(body), text: async () => body };
    },
    put: async (key, body) => { recorded.puts.push(key); store.set(key, String(body)); return {}; },
    delete: async (key) => { store.delete(key); return {}; },
    head: async () => null,
    list: async () => ({ objects: [] }),
  };
}

function makeReport(scanId, domainId, domain, completedAt) {
  return {
    scan_id: scanId, domain_id: domainId, domain, status: "completed",
    cyber_metrics_score: 62, risk_level: "moderate",
    started_at: "2026-07-17T09:00:00.000Z", completed_at: completedAt,
    findings: [
      { id: "email_missing_spf", title: "SPF record missing", description: "No SPF record was found.", severity: "high", module: "email_security", finding_type: "finding", evidence: [] },
      { id: "tls_ciphers_info", title: "TLS observation", description: "Informational.", severity: "info", module: "ssl", finding_type: "observation", evidence: [] },
    ],
    recommendations: [],
    scan_quality: { status: "complete", modules_skipped: [], warnings: [] },
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
    modules: {
      dns: { has_mx: true }, email_security: {}, headers: {}, ssl: {},
      subdomains: { count: 1 }, certificate_intelligence: {},
      brand_monitoring: {}, identity_discovery: { high_risk_count: 0 },
      technology_detection: { count: 1 }, saas_exposure: { count: 0 },
      vendor_relationships: { high_confidence: 0 },
    },
  };
}

async function main() {
  const workerMod = await import(pathToFileURL(srcPath("index.js")).href);
  const worker = workerMod.default;
  const { hashToken, hashPassword } = workerMod;
  const rs = await import(pathToFileURL(srcPath("engines", "report-snapshot.js")).href);
  const { CYBER_MOT_DOMAIN_KEYS } = await import(pathToFileURL(srcPath("engines", "cyber-mot-state-history.js")).href);

  const db = buildDb();
  const writeLog = [];
  const store = new Map();
  const recorded = { puts: [] };
  const env = {
    cybermeters_db: makeD1(db, writeLog),
    cybermeters_reports: makeR2(store, recorded),
    RESEND_API_KEY: "", APP_VERSION: "test",
  };
  const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

  // ── Seed: user + two tenants sharing a hostname + soft-deleted tenant ──────
  const pw = await hashPassword("Sup3r-secret-pw");
  // Plan resolution reads the subscriptions table only (entitlements.js
  // getUserPlan) — an active business subscription entitles scorecard PDFs.
  try {
    db.prepare("INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, current_period_end, created_at) VALUES ('sub1','u1','business','active', datetime('now','+30 day'), datetime('now'))").run();
  } catch (e) { console.error("sub seed:", e.message); }
  db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified, mfa_enabled) VALUES ('u1','o@a.co',?, 'O','business','active',1,0)").run(pw);
  db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES ('s1','u1',?,datetime('now','+1 day'))").run(await hashToken("raw-m5d"));
  for (const [ws, dom] of [["ws1", "dom1"], ["ws2", "dom2"]]) {
    db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?,?,?)").run(ws, "u1", ws === "ws1" ? "Alpha" : "Bravo");
    db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?,?,?,'admin')").run("m-" + ws, ws, "u1");
    db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?,?,'shared.example')").run(dom, "u1");
    db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?,?)").run(ws, dom);
  }
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name, deleted_at) VALUES ('wsDead','u1','Dead',datetime('now'))").run();

  const seedScan = (id, ws, dom, at) => {
    db.prepare("INSERT INTO scans (id, workspace_id, domain_id, domain, score, rating, status, scan_quality, created_at) VALUES (?,?,?,?,62,'moderate','completed','complete',?)")
      .run(id, ws, dom, "shared.example", at);
  };

  // scan1: FINALIZE-built snapshot (live world visible at build time).
  seedScan("scan1", "ws1", "dom1", "2026-07-15 09:05:00");
  const report1 = makeReport("scan1", "dom1", "shared.example", "2026-07-15T09:05:00.000Z");
  store.set("reports/scan1.json", JSON.stringify(report1));
  db.prepare(`INSERT INTO managed_cases (id, workspace_id, case_type, domain_key, domain, finding_id, remediation_id, severity, status, evidence_json, recommended_actions_json, created_at, updated_at)
              VALUES ('mc1','ws1','email_case','email_protection','shared.example','email_missing_spf','email.spf.publish','high','open','{}','[]',datetime('now'),datetime('now'))`).run();
  const b1 = await rs.buildScanReportSnapshot(env, {
    workspaceId: "ws1", domainId: "dom1", scanId: "scan1", domain: "shared.example",
    report: report1, cyberEssentials: null, assessedAt: report1.completed_at,
  });
  ok("finalize-mode snapshot built", b1.status === "completed");

  // scanOld: pre-093 scan, NO attempt — reconstruction happens on first read.
  seedScan("scanOld", "ws2", "dom2", "2026-06-01 10:00:00");
  store.set("reports/scanOld.json", JSON.stringify(makeReport("scanOld", "dom2", "shared.example", "2026-06-01T10:00:00.000Z")));

  const call = async (method, pathname, token = "raw-m5d") => {
    const res = await worker.fetch(new Request("https://api.cybermeters.com" + pathname, {
      method, headers: token ? { Authorization: `Bearer ${token}` } : {},
    }), env, ctx);
    const text = await res.text();
    let data = null; try { data = JSON.parse(text); } catch { /* binary */ }
    return { status: res.status, data, text };
  };

  // ═══ 1-5. Every migrated surface consumes the snapshot; parity matrix ══════
  const snapRes = await call("GET", "/api/scans/scan1/snapshot");
  const truth = snapRes.data?.snapshot;
  ok("snapshot route serves the canonical truth", snapRes.status === 200 && !!truth);

  const repRes = await call("GET", "/api/scans/scan1/report");
  const v2Res = await call("GET", "/api/scans/scan1/executive-report-v2");
  const pdfRes = await call("GET", "/api/scans/scan1/report/pdf");
  const wsPdfRes = await call("GET", "/api/workspaces/ws1/report");
  ok("all four migrated surfaces render", repRes.status === 200 && v2Res.status === 200 && pdfRes.status === 200 && wsPdfRes.status === 200,
     `${repRes.status}/${v2Res.status}/${pdfRes.status}/${wsPdfRes.status}`);
  ok("post-M5.c snapshot-backed report view remains fully available",
     v2Res.status === 200 &&
     !!v2Res.data?.snapshot_id &&
     !v2Res.data?.report_availability);

  const score = truth?.overall?.cyber_metrics_score;
  const band = truth?.overall?.score_band;
  const briBand = truth?.overall?.business_risk_indicator?.band;
  ok("score IDENTICAL across surfaces (value equality)",
     repRes.data?.cyber_metrics_score === score &&
     v2Res.data?.cyber_metrics_score?.value === score &&
     pdfRes.text.includes(`${score} / 100`) &&
     wsPdfRes.text.includes(`${score} / 100`));
  ok("band IDENTICAL across surfaces",
     repRes.data?.risk_level === band &&
     v2Res.data?.cyber_metrics_score?.rating === band &&
     pdfRes.text.includes(`CyberMeters assessment band: ${band}`) &&
     !/Security rating:/i.test(pdfRes.text));
  ok("BRI band IDENTICAL and never a second score",
     repRes.data?.business_risk?.band === briBand &&
     v2Res.data?.business_risk_indicator?.band === briBand &&
     !("score" in (v2Res.data?.business_risk_indicator ?? {})) &&
     pdfRes.text.includes(`Business Risk Indicator: ${String(briBand).toUpperCase()}`));

  // ═══ 6-8. Eight domains fixed order; no five-pillar; no Vendor Risk ════════
  const keys = (arr) => JSON.stringify((arr || []).map((d) => d.domain_key));
  const canonical = JSON.stringify([...CYBER_MOT_DOMAIN_KEYS]);
  ok("exactly eight canonical domains in fixed order on JSON surfaces",
     keys(repRes.data?.cyber_mot_domains) === canonical && keys(v2Res.data?.cyber_mot_domains) === canonical);
  const names = ["Email Protection", "Brand Protection", "Attack Surface", "Certificates & Trust", "Cyber Essentials Readiness", "Website Security", "Identity Exposure", "Shadow IT"];
  const domainSection = pdfRes.text.slice(
    pdfRes.text.indexOf("Eight-Domain Cyber MOT"),
    pdfRes.text.indexOf("Observed Findings")
  );
  ok("scan PDF renders all eight domains in order",
     names.every((n) => domainSection.includes(n)) &&
     names.every((n, i) => i === 0 || domainSection.indexOf(names[i - 1]) < domainSection.indexOf(n)));
  ok("no five-pillar output survives",
     !("intelligence_engines" in (v2Res.data ?? {})) && !v2Res.text.includes("Business Email Intelligence"));
  ok("no Vendor Risk / Supply Chain customer report sections",
     !pdfRes.text.includes("Vendor Risk") && !wsPdfRes.text.includes("Vendor Risk") &&
     !pdfRes.text.includes("Supply Chain & Operational Resilience") && !wsPdfRes.text.includes("Supply Chain & Operational Resilience"));

  // ═══ 9-16. Taxonomy, vocabulary, CE, limitations, methodology, unmapped ════
  ok("Observed Findings taxonomy preserved (never 'verified findings', never merged)",
     Array.isArray(v2Res.data?.observed_findings) && !("verified_findings" in v2Res.data) &&
     pdfRes.text.includes("Observed Findings") &&
     v2Res.data.observed_findings.length === 1 &&
     !v2Res.data.observed_findings.some((o) => o.finding_id === "tls_ciphers_info") &&
     v2Res.data.observations.some((o) => o.finding_id === "tls_ciphers_info"));
  ok("attestation wording never upgraded to Verified/Confirmed",
     !/Verified by customer|Confirmed by customer/i.test(pdfRes.text + v2Res.text));
  ok("CE remains readiness, never certification",
     !/certified|passed Cyber Essentials/i.test(pdfRes.text) &&
     JSON.stringify(v2Res.data.limitations).includes("not a certification"));
  ok("limitations rendered on both PDF and JSON surfaces",
     pdfRes.text.includes("it is not a certification") && (v2Res.data.limitations?.length ?? 0) >= 3);
  // Evidence-Grade Law pilot: formal grade/source/provenance/methodology details
  // belong in the technical appendix, not in the human conclusion blocks.
  ok("assessed_at rendered; formal grade, provenance and methodology versions live in the technical appendix",
     pdfRes.text.includes("Assessed on 15 July 2026") &&
     v2Res.data.assessed_at === truth.snapshot.as_of &&
     pdfRes.text.includes("Technical Appendix - Evidence Grade & Provenance") &&
     pdfRes.text.includes(`Snapshot provenance: ${truth.snapshot.provenance}`) &&
     pdfRes.text.includes(truth.methodology.cyber_mot_resolver_version) &&
     v2Res.data.methodology?.cyber_mot_resolver_version === truth.methodology.cyber_mot_resolver_version);
  const appendixHumanLabels = [
    "Evidence source: CyberMeters product policy",
    "Repeated observation: No",
    "Grade legend",
    "L0-L1: limited or externally-unverified evidence",
    "L2: retained and reproducible",
    "L3+: complete effective-state with stronger provenance",
  ];
  ok("technical appendix uses customer-facing labels and a grade legend",
     appendixHumanLabels.every((text) => pdfRes.text.includes(text)) &&
     !pdfRes.text.includes("source_type=") &&
     !pdfRes.text.includes("repeat_confirmed="),
     appendixHumanLabels.filter((text) => !pdfRes.text.includes(text)).join(", "));
  const scoreBasisIndex = pdfRes.text.indexOf("Evidence confidence:");
  const scoreNumberIndex = pdfRes.text.indexOf(`${score} / 100`);
  ok("score explanation is rendered before the number",
     scoreBasisIndex >= 0 && scoreNumberIndex > scoreBasisIndex);
  const cert = truth.domains.find((d) => d.domain_key === "certificates_trust");
  const ce = truth.domains.find((d) => d.domain_key === "cyber_essentials_readiness");
  ok("certificate conclusion is CT-bounded and never claims live-certificate verification",
     cert?.live_certificate_verified === false &&
     /No material issue in the observed Certificate Transparency evidence/.test(cert?.state_reason || "") &&
     pdfRes.text.includes("No material issue in observed CT evidence"));
  ok("full Cyber Essentials domain never renders healthy over the 2-of-5 external indicator",
     ce?.state !== "assessed_healthy" &&
     ce?.evidence_grade?.grade === "L0" &&
     ce?.evidence_grade?.limits?.some((limit) => /2 of 5|three|attestation/i.test(limit)),
     JSON.stringify(ce));
  ok("overall eight-domain summary carries the minimum domain grade",
     truth.overall?.evidence_grade?.grade === "L0" &&
     v2Res.data?.executive_summary?.evidence_grade?.grade === "L0");
  const spfAction = v2Res.data.remediation_actions.find((a) => a.remediation_id === "email.spf.publish");
  ok("one remediation action carries its finding linkage + ceiling",
     !!spfAction && spfAction.finding_ids.includes("email_missing_spf") && !!spfAction.verification_ceiling);

  // ═══ Reconstruction (founder policy) — pre-093 scan, first authorised read ═
  const oldRep = await call("GET", "/api/scans/scanOld/report");
  ok("pre-093 scan reconstructs on first authorised read", oldRep.status === 200 && oldRep.data?.snapshot_provenance === "reconstructed_on_demand");
  const oldRow = db.prepare("SELECT * FROM scan_report_snapshots WHERE scan_id='scanOld' AND status='completed'").get();
  const oldSnap = JSON.parse(store.get(oldRow.r2_key));
  ok("reconstruction preserves assessed_at as SCAN time, built_at separate",
     oldSnap.snapshot.as_of === "2026-06-01T10:00:00.000Z" && oldSnap.snapshot.built_at !== oldSnap.snapshot.as_of);
  ok("reconstruction NEVER injects current case/CE state",
     oldSnap.domains.every((d) => d.managed_workflow?.unavailable === true) &&
     oldSnap.domains.find((d) => d.domain_key === "cyber_essentials_readiness").cyber_essentials === null &&
     oldSnap.limitations.some((l) => l.includes("reconstructed on demand")));
  // Composer-level defence in depth: even if a caller HANDS current case rows
  // to a reconstruction compose, they must not reach the snapshot.
  const reconDirect = rs.composeSnapshot({
    snapshotId: "snap_rd", workspaceId: "ws1", domainId: "dom1", scanId: "scan_rd",
    domain: "shared.example", report: report1, cyberEssentials: { status: "not_assessed" },
    ceReadiness: null,
    caseRows: [{ id: "mcX", workspace_id: "ws1", case_type: "email_case", domain_key: "email_protection", finding_id: "email_missing_spf", remediation_id: "email.spf.publish", status: "open" }],
    questionSetVersions: ["2026-07-16"], supersedesSnapshotId: null,
    builtAt: "2026-07-17T00:00:00.000Z", reconstruction: true,
  });
  ok("composer refuses injected current case state under reconstruction",
     reconDirect.observed_findings.every((i) => i.managed_case_id === null) &&
     reconDirect.remediation_actions.every((a) => a.case_id === null) &&
     reconDirect.domains.every((d) => d.managed_workflow?.unavailable === true));

  const oldRep2 = await call("GET", "/api/scans/scanOld/report");
  ok("later requests serve the SAME immutable reconstruction",
     oldRep2.data?.snapshot_id === oldRep.data?.snapshot_id &&
     db.prepare("SELECT COUNT(*) c FROM scan_report_snapshots WHERE scan_id='scanOld'").get().c === 1);

  // A genuinely pre-M5.c report without the completion timestamp required for
  // honest reconstruction cannot produce a canonical snapshot. The Executive
  // view returns a calm historical boundary (200), while the technical report
  // remains honestly unavailable — never a fabricated snapshot.
  seedScan("scanPreSnapshot", "ws1", "dom1", "2026-06-01 08:00:00");
  const preSnapshotReport = makeReport(
    "scanPreSnapshot",
    "dom1",
    "shared.example",
    "2026-06-01T08:00:00.000Z"
  );
  delete preSnapshotReport.completed_at;
  store.set("reports/scanPreSnapshot.json", JSON.stringify(preSnapshotReport));
  const preSnapshotExecutive = await call("GET", "/api/scans/scanPreSnapshot/executive-report-v2");
  const preSnapshotTechnical = await call("GET", "/api/scans/scanPreSnapshot/report");
  ok("pre-snapshot completed scan returns an honest non-error availability state",
     preSnapshotExecutive.status === 200 &&
     preSnapshotExecutive.data?.report_availability?.status === "historical_scan_no_canonical_snapshot" &&
     /predates the canonical report snapshot/.test(preSnapshotExecutive.data?.report_availability?.message || "") &&
     /17 July 2026 onward/.test(preSnapshotExecutive.data?.report_availability?.message || ""));
  ok("pre-snapshot availability state does not fabricate a snapshot or imply data loss",
     !preSnapshotExecutive.data?.snapshot_id &&
     !/data loss|something went wrong|retry/i.test(preSnapshotExecutive.data?.report_availability?.message || "") &&
     preSnapshotTechnical.status === 404 &&
     db.prepare("SELECT COUNT(*) c FROM scan_report_snapshots WHERE scan_id='scanPreSnapshot'").get().c === 0);

  // ═══ Live-mutation-after-completion: history cannot be rewritten ═══════════
  const pdfBefore = pdfRes.text;
  const writesBeforeRenders = writeLog.length; // builder/reconstruction writes above are legitimate
  db.prepare("UPDATE managed_cases SET status='closed' WHERE id='mc1'").run();
  db.prepare("UPDATE scans SET score = 5, rating = 'critical' WHERE id='scan1'").run();
  const repAfter = await call("GET", "/api/scans/scan1/report");
  const pdfAfter = await call("GET", "/api/scans/scan1/report/pdf");
  ok("live-table changes do NOT change rendered historical facts",
     repAfter.data?.cyber_metrics_score === score &&
     repAfter.data?.risk_level === band &&
     pdfAfter.text === pdfBefore);
  ok("repeated rendering is deterministic (byte-identical PDF)",
     (await call("GET", "/api/scans/scan1/report/pdf")).text === pdfBefore);
  ok("renders performed ZERO new writes to the immutable snapshot store",
     writeLog.length === writesBeforeRenders, writeLog.slice(writesBeforeRenders).join(" | "));

  // ═══ Failure states through real renderers ═════════════════════════════════
  const row1 = db.prepare("SELECT r2_key, checksum_sha256 FROM scan_report_snapshots WHERE scan_id='scan1'").get();
  const goodBytes = store.get(row1.r2_key);
  store.set(row1.r2_key, goodBytes + " ");
  const corrupt = await call("GET", "/api/scans/scan1/report/pdf");
  ok("checksum mismatch fails closed on the PDF renderer (500, no content)",
     corrupt.status === 500 && !corrupt.text.includes("Observed Findings"));
  store.delete(row1.r2_key);
  ok("missing R2 behind completed row fails closed (500)",
     (await call("GET", "/api/scans/scan1/report")).status === 500);
  store.set(row1.r2_key, goodBytes);

  // Unknown schema version: recompute checksum so ONLY the version gate fires.
  const poisoned = JSON.parse(goodBytes);
  poisoned.snapshot.snapshot_schema_version = "999";
  const pBytes = JSON.stringify(poisoned, null, 2);
  db.prepare("UPDATE scan_report_snapshots SET snapshot_schema_version='999', checksum_sha256=? WHERE scan_id='scan1'")
    .run(await rs.snapshotSha256Hex(pBytes));
  store.set(row1.r2_key, pBytes);
  const directUnknown = await rs.readScanReportSnapshot(env, "scan1", { repair: false });
  const unknown = await call("GET", "/api/scans/scan1/report");
  ok("unknown snapshot schema version is rejected by the shared helper for the intended reason",
     directUnknown.status === "unsupported_schema_version" && directUnknown.reason === "schema_999");
  ok("unknown snapshot schema version fails safely at the renderer boundary (500, no misrender, no legacy fallback)",
     unknown.status === 500 &&
     !String(unknown.text).includes("cyber_mot_domains"));
  db.prepare("UPDATE scan_report_snapshots SET snapshot_schema_version='1', checksum_sha256=? WHERE scan_id='scan1'").run(row1.checksum_sha256);
  store.set(row1.r2_key, goodBytes);

  // Building row → retryable 409 on renderers.
  seedScan("scan_b", "ws1", "dom1", "2026-07-17 09:30:00");
  store.set("reports/scan_b.json", JSON.stringify(makeReport("scan_b", "dom1", "shared.example", "2026-07-17T09:30:00.000Z")));
  db.prepare(`INSERT INTO scan_report_snapshots (id, workspace_id, domain_id, scan_id, status, r2_key, snapshot_schema_version, resolver_version, assessed_at)
              VALUES ('snap-bld','ws1','dom1','scan_b','building','reports/snapshots/ws1/scan_b/x.json','1','v','2026-07-17T09:30:00.000Z')`).run();
  ok("building snapshot is retryable (409) on the report renderer",
     (await call("GET", "/api/scans/scan_b/report")).status === 409);

  // ═══ Tenant + soft-delete ═════════════════════════════════════════════════
  const ws2Pdf = await call("GET", "/api/workspaces/ws2/report");
  ok("same hostname in two tenants stays isolated (ws2 PDF never carries ws1 ids)",
     ws2Pdf.status === 200 && !ws2Pdf.text.includes("scan1") && !ws2Pdf.text.includes(String(row1.r2_key)));
  ok("no raw snapshot R2 keys leak into any customer output (JSON and PDF bytes)",
     ![repRes, v2Res, oldRep, pdfRes, wsPdfRes].some((r) => String(r.text).includes("reports/snapshots/")));
  ok("the certificate not-checked disclosure reaches the rendered PDF verbatim",
     /OCSP/.test(pdfRes.text) && /revocation/.test(pdfRes.text));

  // Branding diff-confinement: a branded render may differ ONLY in branding
  // strings — every security fact byte survives unchanged.
  {
    const brandedPdf = await (async () => {
      db.prepare("UPDATE users SET plan='business' WHERE id='u1'").run();
      db.prepare("INSERT INTO customer_profiles (id, owner_user_id, company_name, brand_accent, report_white_label) VALUES ('cp1','u1','Acme MSP','#7C3AED',1)").run();
      // The earlier unbranded render lazily FROZE branding_json (v2 determinism);
      // clear it so this render re-resolves with the new brand — this test proves
      // renderer diff-confinement, not freeze (freeze is covered separately).
      db.prepare("UPDATE scan_report_snapshots SET branding_json = NULL WHERE scan_id='scan1'").run();
      return call("GET", "/api/scans/scan1/report/pdf");
    })();
    // Brand-string normaliser. Removes every branding token (v1 legacy AND v2
    // wording) so only the SECURITY FACTS remain for comparison. The v2 white-label
    // footer is "<name> | Powered by CyberMeters | app.cybermeters.com"; co-brand /
    // fallback footer is "Generated by CyberMeters | app.cybermeters.com".
    const stripBrand = (t) => t
      .replaceAll("Acme MSP", "").replaceAll("CyberMeters", "")
      .replaceAll("Prepared by  | Powered by ", "")
      .replaceAll(" | Powered by  | app.cybermeters.com", "")
      .replaceAll("Generated by  | app.cybermeters.com", "")
      .replace(/0\.05 0\.30 0\.62 rg|[0-9.]+ [0-9.]+ [0-9.]+ rg/g, "rg")
      .replace(/\/Length \d+/g, "/Length N").replace(/^\d{10} 00000 n $/gm, "OFF").replace(/startxref\n\d+/g, "startxref N");
    ok("branded render differs ONLY in branding (facts byte-identical after stripping brand strings)",
       brandedPdf.status === 200 && stripBrand(brandedPdf.text) === stripBrand(pdfBefore) &&
       brandedPdf.text.includes("Acme MSP"));
    ok("scorecard PDF route renders snapshot facts for the entitled owner",
       await call("GET", "/api/workspaces/ws1/scorecard/pdf").then((r) => r.status === 200 && r.text.includes(`${score} / 100`)));
    const pd = await call("GET", "/api/workspaces/ws1/scorecard/pdf-data");
    ok("scorecard pdf-data serves the verified snapshot contract shape",
       pd.status === 200 && pd.data?.workspace?.id === "ws1" &&
       pd.data.snapshots.some((x) => x.status === "ok" && x.snapshot?.overall?.cyber_metrics_score === score));
    db.prepare("UPDATE customer_profiles SET report_white_label=0 WHERE owner_user_id='u1'").run();
  }

  // Historical-scan trend baseline is tenant-scoped (the M5.d security fix):
  // two tenants share a hostname; neither may diff against the other's scan.
  {
    const { runHistoricalModule } = await import(pathToFileURL(srcPath("engines", "historical-scan.js")).href);
    const hcWs1 = await runHistoricalModule("scan_hc", "shared.example", 50, [], {}, env, "ws1");
    ok("trend baseline stays inside the tenant (ws1 finds only its own prior scan)",
       hcWs1.previous_scan_id === "scan1" || hcWs1.previous_scan_id === "scan_b");
    const hcNull = await runHistoricalModule("scan_hc2", "shared.example", 50, [], {}, env, null);
    ok("a legacy NULL-workspace scan gets NO cross-tenant baseline",
       hcNull.has_previous === false && hcNull.previous_scan_id === null);
  }

  // A completed legacy scan with NO workspace attribution cannot reconstruct —
  // honest 404, zero snapshot rows created (tenant-strict founder policy).
  {
    db.prepare("INSERT INTO scans (id, workspace_id, domain_id, domain, score, rating, status, scan_quality, created_at) VALUES ('scanNullWs',NULL,'dom1','shared.example',62,'moderate','completed','complete','2026-06-01 09:00:00')").run();
    store.set("reports/scanNullWs.json", JSON.stringify(makeReport("scanNullWs", "dom1", "shared.example", "2026-06-01T09:00:00.000Z")));
    ok("NULL-workspace legacy scan is honestly unavailable (404, no build)",
       (await call("GET", "/api/scans/scanNullWs/report")).status === 404 &&
       db.prepare("SELECT COUNT(*) c FROM scan_report_snapshots WHERE scan_id='scanNullWs'").get().c === 0);
  }

  // Stored executive report generator: snapshot binding + soft-delete guard.
  {
    const { generateWorkspaceExecutiveReport } = await import(pathToFileURL(srcPath("engines", "plan-usage.js")).href);
    const row = await generateWorkspaceExecutiveReport("ws1", env, { report_type: "manual" });
    const meta = JSON.parse(db.prepare("SELECT metadata_json FROM workspace_reports WHERE id=?").get(row.id).metadata_json);
    ok("stored executive PDF is bound to the exact immutable snapshots it rendered",
       row.status === "completed" && Array.isArray(meta.snapshots) && meta.snapshots.some((b) => b.scan_id === "scan1" && b.checksum_sha256));
    let deadThrew = false;
    try { await generateWorkspaceExecutiveReport("wsDead", env, { report_type: "manual" }); } catch { deadThrew = true; }
    ok("stored report generation refuses a soft-deleted workspace", deadThrew);
  }
  ok("soft-deleted workspace does not render", (await call("GET", "/api/workspaces/wsDead/report")).status !== 200);
  ok("anonymous callers denied on every migrated surface",
     (await call("GET", "/api/scans/scan1/report", null)).status === 401 &&
     (await call("GET", "/api/workspaces/ws1/report", null)).status === 401);

  // ═══ Legacy calculations unreachable from migrated paths (static) ══════════
  const strip = (s) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  const scansSrc = strip(fs.readFileSync(srcPath("routes", "scans.js"), "utf8"));
  const pdfSrc = strip(fs.readFileSync(srcPath("engines", "pdf.js"), "utf8"));
  const erSrc = strip(fs.readFileSync(srcPath("engines", "executive-report.js"), "utf8"));
  const BRAINS = /resolveCyberMotDomainStates|deriveScanBusinessRisk|computeBusinessRiskScore|computeSecurityPosture|resolveAssessmentPresentation|buildCyberEssentialsReadiness|buildScorecardData|resolveCanonicalScanScore/;
  ok("routes/scans.js render paths import no calculation brain", !BRAINS.test(scansSrc));
  ok("pdf.js imports no calculation brain", !BRAINS.test(pdfSrc));
  ok("executive-report.js imports no calculation brain", !BRAINS.test(erSrc));
  ok("legacy PDF brains are deleted, not unreferenced",
     !/collectPdfData|buildExecutivePdf\b|buildPdfStreams/.test(pdfSrc));

  console.log(`\nM5.d renderer migration: ${pass}/${pass + fail} passed`);
  if (fail) { console.error("m5d-renderer-migration validation FAILED"); process.exit(1); }

  // ═══ Mutations — each guard must catch its reintroduced defect ═════════════
  if (!process.argv.includes("--no-mutate")) {
    const MUTATIONS = [
      {
        name: "report route re-derives the score from live scan row",
        file: srcPath("routes", "scans.js"),
        from: "          cyber_metrics_score: overall.cyber_metrics_score ?? null,\n          risk_level: overall.score_band ?? null,",
        to:   "          cyber_metrics_score: scan.score ?? null,\n          risk_level: scan.rating ?? null,",
      },
      {
        name: "renderer drops a domain (seven survive)",
        file: srcPath("engines", "executive-report.js"),
        from: "    cyber_mot_domains: snap.domains ?? [],",
        to:   "    cyber_mot_domains: (snap.domains ?? []).slice(0, 7),",
      },
      {
        name: "five-pillar intelligence_engines returns to the response",
        file: srcPath("engines", "executive-report.js"),
        from: "    cyber_mot_domains: snap.domains ?? [],",
        to:   "    intelligence_engines: { attack_surface: {}, business_email: {}, identity: {}, brand: {}, executive: {} },\n    cyber_mot_domains: snap.domains ?? [],",
      },
      {
        name: "Vendor Risk section returns to the PDF",
        file: srcPath("engines", "pdf.js"),
        from: "function sectionMethodology(w, snap) {",
        to:   "function sectionMethodology(w, snap) {\n  w.heading(\"Vendor Risk\");",
      },
      {
        name: "observations merged into Observed Findings (taxonomy collapse)",
        file: srcPath("engines", "executive-report.js"),
        from: "  const observed = Array.isArray(snap.observed_findings) ? snap.observed_findings : [];",
        to:   "  const observed = [...(snap.observed_findings ?? []), ...(snap.observations ?? [])];",
      },
      {
        name: "limitations dropped from the PDF",
        file: srcPath("engines", "pdf.js"),
        from: "  for (const l of snap.limitations || []) w.proseKeep(`- ${l}`, { size: 8, color: \"0.35 0.38 0.44\" });",
        to:   "  ;",
      },
      {
        name: "score number rendered before its evidence basis",
        file: srcPath("engines", "pdf.js"),
        from: "  evidenceConfidenceBlock(w, o.assessment_evidence_grade);",
        to:   "  ;",
      },
      {
        name: "product-policy band relabelled as Security rating",
        file: srcPath("engines", "pdf.js"),
        from: "  if (o.score_band) w.text(`CyberMeters assessment band: ${o.score_band}`, { size: 11 });",
        to:   "  if (o.score_band) w.text(`Security rating: ${o.score_band}`, { size: 11 });",
      },
      {
        name: "Evidence-Grade technical appendix dropped",
        file: srcPath("engines", "pdf.js"),
        from: "  sectionEvidenceGradeAppendix(w, snap);",
        to:   "  ;",
      },
      {
        name: "pre-snapshot historical boundary mapped back to a red report error",
        file: srcPath("routes", "scans.js"),
        from: "          const availability = historicalReportSnapshotAvailability(scan);",
        to:   "          const availability = null;",
      },
      {
        name: "schema-version gate dropped from the shared helper",
        file: srcPath("engines", "report-snapshot.js"),
        from: "  if (!SUPPORTED_SNAPSHOT_SCHEMA_VERSIONS.has(String(row.snapshot_schema_version))) {",
        to:   "  if (false) {",
      },
      {
        name: "reconstruction injects current managed-case state",
        file: srcPath("engines", "report-snapshot.js"),
        from: "  const rows = reconstruction ? [] : (Array.isArray(caseRows) ? caseRows : []);",
        to:   "  const rows = Array.isArray(caseRows) ? caseRows : [];",
      },
      {
        name: "reconstruction workflow summary claims zero cases instead of unavailable",
        file: srcPath("engines", "report-snapshot.js"),
        from: "      managed_workflow: reconstruction\n        ? WORKFLOW_UNAVAILABLE\n        : (workflowByDomain.get(d.domain_key) || { total_cases: 0, open_cases: 0, statuses: {} }),",
        to:   "      managed_workflow: (workflowByDomain.get(d.domain_key) || { total_cases: 0, open_cases: 0, statuses: {} }),",
      },
      {
        name: "renderer writes to the snapshot store on render",
        file: srcPath("routes", "scans.js"),
        from: "        const snap = read.snapshot;\n        const overall = snap.overall || {};",
        to:   "        await env.cybermeters_db.prepare(\"UPDATE scan_report_snapshots SET metadata_json='rendered' WHERE scan_id = ?\").bind(scanId).run();\n        const snap = read.snapshot;\n        const overall = snap.overall || {};",
      },
      {
        name: "PDF reads the request clock instead of the snapshot's as_of",
        file: srcPath("engines", "pdf.js"),
        from: "  w.text(`Assessed on ${pdfUtcDate(s.as_of, true)}`, { size: 10, bold: true });",
        to:   "  w.text(`Assessed on ${pdfUtcDate(new Date().toISOString(), true)}`, { size: 10, bold: true });",
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
    if (mfail) { console.error("m5d-renderer-migration mutation validation FAILED"); process.exit(1); }
  }

  console.log("m5d-renderer-migration validation passed");
}

main().catch((e) => { console.error("m5d-renderer-migration runner crashed:", e); process.exit(1); });
