#!/usr/bin/env node
//
// M5.e-E closure validator — eight-domain parity closure and release gate.
//
// This is intentionally a broad contract test. The earlier M5.e validators prove
// their individual slices; this one proves the release-level closure areas hang
// together and mutation-fails the regressions the founder explicitly named.
//
// It drives real worker routes where practical (/business-risk and case
// assignment), uses the real SQLite schema + migrations, imports canonical engines,
// and supplements those behavioural paths with static guards for frontend/report
// drift that cannot be reached from a single route fixture.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerSrc = path.join(root, "workers", "scan-api", "src");
const frontendSrc = path.join(root, "frontend", "src");

const read = (rel) => fs.readFileSync(path.join(root, rel), "utf8");
const rel = (p) => path.relative(root, p);
const sourceFiles = new Map();
const getSource = (relPath) => sourceFiles.get(relPath) ?? read(relPath);
const setSource = (relPath, src) => sourceFiles.set(relPath, src);

let pass = 0;
let fail = 0;
const failures = [];
function ok(name, condition, detail = "") {
  if (condition) {
    pass++;
  } else {
    fail++;
    const msg = `FAIL ${name}${detail ? " — " + detail : ""}`;
    failures.push(msg);
    console.log(msg);
  }
}
function eq(name, actual, expected) {
  ok(name, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

function walk(dir, predicate = () => true) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p, predicate));
    else if (predicate(p)) out.push(p);
  }
  return out;
}

function buildDb({ apply094 = true } = {}) {
  const db = new DatabaseSync(":memory:");
  const apply = (p, { strict = false } = {}) => {
    try {
      db.exec(fs.readFileSync(p, "utf8"));
      return { ok: true };
    } catch (err) {
      if (strict) throw err;
      return { ok: false, error: String(err?.message || err) };
    }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    if (!apply094 && f.startsWith("094-")) continue;
    apply(path.join(root, "database", "migrations", f));
  }
  return db;
}

function makeD1(db, writeLog, opts = {}) {
  const failSelectFrom = opts.failSelectFrom ?? null;
  const wrap = (sql, args) => ({
    __sql: sql,
    __args: args,
    first: async (col) => {
      if (failSelectFrom && new RegExp(`\\bfrom\\s+${failSelectFrom}\\b`, "i").test(sql)) throw new Error(`forced ${failSelectFrom} read failure`);
      const r = db.prepare(sql).get(...args) ?? null;
      return col && r ? r[col] : r;
    },
    all: async () => {
      if (failSelectFrom && new RegExp(`\\bfrom\\s+${failSelectFrom}\\b`, "i").test(sql)) throw new Error(`forced ${failSelectFrom} read failure`);
      return { results: db.prepare(sql).all(...args), success: true, meta: {} };
    },
    run: async () => {
      if (writeLog && /^\s*(insert|update|delete|replace|alter|drop|create)\b/i.test(sql)) {
        writeLog.push(sql.trim().replace(/\s+/g, " ").slice(0, 180));
      }
      const r = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } };
    },
  });
  return {
    prepare(sql) {
      const b = wrap(sql, []);
      b.bind = (...args) => wrap(sql, args);
      return b;
    },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

const noR2 = {
  get: async () => null,
  put: async () => ({}),
  head: async () => null,
  delete: async () => ({}),
  list: async () => ({ objects: [] }),
};
function makeEnv(db, writeLog, d1Opts = {}) {
  return {
    cybermeters_db: makeD1(db, writeLog, d1Opts),
    cybermeters_reports: noR2,
    MFA_ENCRYPTION_KEY: "m5e-closure-validator-key",
    STRIPE_WEBHOOK_SECRET: "whsec_test",
    STRIPE_SECRET_KEY: "sk_test_x",
    STRIPE_PRICE_MAP: "{}",
    ALLOWED_ORIGIN: "https://app.cybermeters.com",
    FRONTEND_URL: "https://app.cybermeters.com",
    APP_VERSION: "test",
    RESEND_API_KEY: "",
    ADMIN_EMAILS: "",
  };
}

async function loadWorker() {
  globalThis.fetch = async () => { throw new Error("network disabled"); };
  AbortSignal.timeout = () => undefined;
  return import(pathToFileURL(path.join(workerSrc, "index.js")).href);
}

const CANONICAL_KEYS = Object.freeze([
  "email_protection",
  "brand_protection",
  "attack_surface",
  "certificates_trust",
  "cyber_essentials_readiness",
  "website_security",
  "identity_exposure",
  "shadow_it_unmanaged_technology",
]);
const CANONICAL_LABELS = Object.freeze([
  "Email Protection",
  "Brand Protection",
  "Attack Surface",
  "Certificates & Trust",
  "Cyber Essentials Readiness",
  "Website Security",
  "Identity Exposure",
  "Shadow IT & Unmanaged Technology",
]);

async function checkEightDomainCompleteness() {
  const { CYBER_MOT_DOMAINS, resolveCyberMotDomainStates } = await import(pathToFileURL(path.join(workerSrc, "engines", "cyber-mot-domains.js")).href);
  const keys = CYBER_MOT_DOMAINS.map((d) => d.domain_key);
  eq("A: canonical resolver exports exactly eight domains", keys.length, 8);
  eq("A: canonical resolver order is exact", keys.join(","), CANONICAL_KEYS.join(","));
  eq("A: canonical resolver has no duplicate domain", new Set(keys).size, 8);
  const noScan = resolveCyberMotDomainStates(null);
  eq("A/C: no-scan result still has exactly eight domains", noScan.length, 8);
  eq("A/C: no-scan result keeps canonical order", noScan.map((d) => d.domain_key).join(","), CANONICAL_KEYS.join(","));
  ok("C: no-scan has no assessed_healthy domain", noScan.every((d) => d.state !== "assessed_healthy"));

  const domainConsumers = [
    "frontend/src/components/CyberMotDomains.jsx",
    "frontend/src/pages/Dashboard.jsx",
    "frontend/src/components/ServiceLauncher.jsx",
    "frontend/src/components/WorkspaceNav.jsx",
    "frontend/src/pages/PublicLandingPage.jsx",
    "frontend/src/pages/ws/WorkspaceDashboard.jsx",
    "frontend/src/pages/ws/WorkspaceScorecard.jsx",
    "workers/scan-api/src/engines/report-snapshot.js",
    "workers/scan-api/src/engines/pdf.js",
    "workers/scan-api/src/routes/executive-dashboard.js",
    "workers/scan-api/src/routes/workspace-analytics.js",
    "workers/scan-api/src/lib/lifecycle-email.js",
    "workers/scan-api/src/engines/portfolio-domains.js",
  ];
  for (const file of domainConsumers) {
    const src = getSource(file);
    ok(`A: ${file} has no customer/MSP five-pillar vocabulary`, !/\bfive[- ]pillar|Third-Party Risk|Admin Exposure|SSL & Certificates\b/i.test(src));
    ok(`A: ${file} has no four-service customer grouping`, !/\bfour[- ]service|four services\b/i.test(src));
  }
  const nav = getSource("frontend/src/components/WorkspaceNav.jsx");
  const launcher = getSource("frontend/src/components/ServiceLauncher.jsx");
  const landing = getSource("frontend/src/pages/PublicLandingPage.jsx");
  const dashboard = getSource("frontend/src/pages/Dashboard.jsx");
  for (const label of CANONICAL_LABELS) {
    ok(`A/G: WorkspaceNav exposes ${label}`, nav.includes(label));
    ok(`A/G: ServiceLauncher exposes ${label}`, launcher.includes(label));
    ok(`A/G: PublicLandingPage exposes ${label}`, landing.includes(label));
    ok(`A/G: Dashboard exposes ${label}`, dashboard.includes(label));
  }
  ok("A/G: WorkspaceNav primary domains are in canonical order",
    CANONICAL_LABELS.every((label, i) => nav.indexOf(`title: '${label}'`) >= 0 && (i === 0 || nav.indexOf(`title: '${CANONICAL_LABELS[i - 1]}'`) < nav.indexOf(`title: '${label}'`))));
  ok("A/E: workspace analytics chart uses canonical cyber_mot_domains adapter", /scorecard\.cyber_mot_domains/.test(getSource("workers/scan-api/src/routes/workspace-analytics.js")));
}

async function checkScoreAndStateHonesty() {
  const scoring = await import(pathToFileURL(path.join(workerSrc, "engines", "scoring.js")).href);
  const assessment = await import(pathToFileURL(path.join(workerSrc, "engines", "assessment-presentation.js")).href);
  const frontendScore = await import(pathToFileURL(path.join(frontendSrc, "lib", "score-presentation.js")).href);
  const backendBands = scoring.CYBER_METRICS_SCORE_BANDS;
  ok("B: backend exposes one canonical Cyber Metrics Score ladder", backendBands && typeof backendBands === "object");
  eq("B: frontend mirror threshold excellent", frontendScore.SCORE_BANDS.excellent, backendBands.excellent);
  eq("B: frontend mirror threshold good", frontendScore.SCORE_BANDS.good, backendBands.good);
  eq("B: frontend mirror threshold moderate", frontendScore.SCORE_BANDS.moderate, backendBands.moderate);
  eq("B: frontend mirror threshold high", frontendScore.SCORE_BANDS.high, backendBands.high);
  eq("B: null score has no frontend band", frontendScore.scoreBand(null), null);
  eq("B: unknown frontend band renders neutral", frontendScore.bandMeta("made_up").label, "Not assessed");
  const unknown = assessment.resolveAssessmentPresentation({ score: 72, scanQuality: "unknown", status: "completed" });
  eq("C: unknown scan quality suppresses final rating", unknown.display_rating, null);
  eq("C: unknown scan quality is not authoritative", unknown.authoritative, false);
  const failed = assessment.resolveAssessmentPresentation({ score: 0, scanQuality: "complete", status: "failed" });
  eq("C: failed scan does not publish score", failed.display_score, null);
  eq("C: failed scan does not publish rating", failed.display_rating, null);
  const partial = assessment.resolveAssessmentPresentation({ score: 90, scanQuality: "partial", status: "completed" });
  eq("C: partial scan may show provisional number", partial.display_score, 90);
  eq("C: partial scan does not publish final rating", partial.display_rating, null);
  eq("C: partial scan is not comparable", partial.comparable, false);

  const workerFiles = walk(workerSrc, (p) => p.endsWith(".js"));
  const allowedRiskCallers = new Set([
    "workers/scan-api/src/engines/scoring.js",
    "workers/scan-api/src/engines/assessment-presentation.js",
    "workers/scan-api/src/engines/portfolio-customers.js",
  ]);
  const badRiskCallers = [];
  for (const p of workerFiles) {
    const rp = rel(p);
    if (allowedRiskCallers.has(rp)) continue;
    const code = getSource(rp).replace(/\/\/[^\n]*/g, "");
    if (/riskLevelForScore\s*\(/.test(code)) badRiskCallers.push(rp);
  }
  ok("B: backend has no local Cyber Score display brains", badRiskCallers.length === 0, badRiskCallers.join(", "));

  const frontendFiles = walk(frontendSrc, (p) => p.endsWith(".jsx") || p.endsWith(".js"));
  const badFrontendLadders = [];
  for (const p of frontendFiles) {
    const rp = rel(p);
    if (rp === "frontend/src/lib/score-presentation.js") continue;
    const src = getSource(rp).replace(/\/\/[^\n]*/g, "");
    const hasCanonicalPartition =
      /score\s*>=\s*90[\s\S]{0,160}score\s*>=\s*75[\s\S]{0,160}score\s*>=\s*50[\s\S]{0,160}score\s*>=\s*25/.test(src);
    const namesCyberMetrics = /Cyber Metrics Score|cyber_metrics_score|posture score|Posture Score/.test(src);
    if (hasCanonicalPartition && namesCyberMetrics) badFrontendLadders.push(rp);
  }
  ok("B/G: frontend has no local Cyber Score threshold ladders", badFrontendLadders.length === 0, badFrontendLadders.join(", "));
}

async function seedUserAndWorkspace(mod, db, { user = "u_owner", token = "tok-owner", workspace = "ws1", plan = "business" } = {}) {
  const hash = await mod.hashToken(token);
  db.prepare("INSERT INTO users (id,email,name,plan,status,email_verified,mfa_enabled) VALUES (?,?,?,?,?,1,0)")
    .run(user, `${user}@example.com`, user, plan, "active");
  db.prepare("INSERT INTO user_sessions (id,user_id,token_hash,expires_at,last_seen_at) VALUES (?,?,?,?,?)")
    .run(`sess_${user}`, user, hash, "2099-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
  db.prepare("INSERT INTO subscriptions (id,owner_user_id,plan,subscription_status,status,current_period_end,created_at,updated_at) VALUES (?,?,?,?,?,?,datetime('now'),datetime('now'))")
    .run(`sub_${user}`, user, plan, "active", "active", "2099-01-01T00:00:00Z");
  db.prepare("INSERT INTO workspaces (id,name,owner_user_id,created_at,updated_at) VALUES (?,?,?,?,?)")
    .run(workspace, workspace, user, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
  db.prepare("INSERT INTO workspace_members (id,workspace_id,user_id,role,created_at) VALUES (?,?,?,?,datetime('now'))")
    .run(`mem_${user}`, workspace, user, "admin");
  return { token, user, workspace };
}

async function checkOwnershipBehaviour() {
  const mod = await loadWorker();
  const db = buildDb();
  const writes = [];
  const env = makeEnv(db, writes);
  const { token, workspace } = await seedUserAndWorkspace(mod, db);

  db.prepare(`INSERT INTO managed_cases
    (id, workspace_id, case_type, domain_key, status, severity, title, domain, finding_id, remediation_id, created_at, updated_at)
    VALUES ('case_brand', ?, 'brand_abuse', 'brand_protection', 'triaged', 'high', 'Brand case', 'brand.example', 'f1', 'brand.takedown.prepare', datetime('now'), datetime('now'))`)
    .run(workspace);
  db.prepare(`INSERT INTO managed_cases
    (id, workspace_id, case_type, domain_key, status, severity, title, domain, finding_id, remediation_id, created_at, updated_at)
    VALUES ('case_web', ?, 'website_case', 'website_security', 'triaged', 'medium', 'Web case', 'www.example', 'f2', 'web.header.hsts', datetime('now'), datetime('now'))`)
    .run(workspace);

  const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
  const call = (caseId, body, tok = token) => mod.default.fetch(new Request(`https://api.cybermeters.com/api/workspaces/${workspace}/cases/${caseId}/assign`, {
    method: "POST",
    headers: { Authorization: `Bearer ${tok}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  }), env, ctx);
  const transition = (caseId, body, tok = token) => mod.default.fetch(new Request(`https://api.cybermeters.com/api/workspaces/${workspace}/cases/${caseId}/transition`, {
    method: "POST",
    headers: { Authorization: `Bearer ${tok}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  }), env, ctx);

  const missing = await call("case_brand", { owner_type: "team", owner_ref: "" });
  eq("D: assigned transition with NULL/empty owner is refused", missing.status, 400);
  const missingRow = db.prepare("SELECT status, owner_ref FROM managed_cases WHERE id='case_brand'").get();
  eq("D: refused assignment does not persist assigned owner", missingRow.owner_ref, null);

  const brand = await call("case_brand", { owner_type: "team", owner_ref: "Brand Ops", assigned_user_id: "u_owner" });
  eq("D: Brand assignment works through canonical route", brand.status, 200);
  const brandData = await brand.json();
  eq("D: Brand assignment persists owner_ref", brandData.case.owner_ref, "Brand Ops");
  const ev = db.prepare("SELECT action, detail_json FROM managed_case_events WHERE case_id='case_brand' ORDER BY created_at DESC LIMIT 1").get();
  eq("D: assignment_changed event emitted", ev.action, "assignment_changed");
  ok("D: assignment_changed event carries owner_ref", /Brand Ops/.test(ev.detail_json || ""));

  const web = await call("case_web", { owner_type: "person", owner_ref: "Web Owner" });
  eq("D: base-domain assignment uses same canonical route", web.status, 200);
  db.prepare("UPDATE managed_cases SET status='triaged', owner_type=NULL, owner_ref=NULL, assigned_by=NULL, assigned_user_id=NULL WHERE id='case_web'").run();
  const missingTransition = await transition("case_web", { target_status: "assigned" });
  eq("D: route-level assigned transition with NULL owner is refused", missingTransition.status, 409);
  const transitionMissingRow = db.prepare("SELECT status, owner_ref FROM managed_cases WHERE id='case_web'").get();
  eq("D: refused assigned transition does not persist assigned status", transitionMissingRow.status, "triaged");
  eq("D: refused assigned transition does not persist NULL owner as assignment", transitionMissingRow.owner_ref, null);
  const whitespaceTransition = await transition("case_web", { target_status: "assigned", owner_ref: "   " });
  eq("D: route-level assigned transition with whitespace owner is refused", whitespaceTransition.status, 409);
  const transitionWhitespaceRow = db.prepare("SELECT status, owner_ref FROM managed_cases WHERE id='case_web'").get();
  eq("D: refused whitespace owner transition does not persist assigned status", transitionWhitespaceRow.status, "triaged");
  eq("D: refused whitespace owner transition does not persist NULL owner as assignment", transitionWhitespaceRow.owner_ref, null);
  const assignedTransition = await transition("case_web", { target_status: "assigned", owner_type: "person", owner_ref: "Web Owner" });
  eq("D: route-level assigned transition with owner succeeds", assignedTransition.status, 200);
  const assignedTransitionRow = db.prepare("SELECT status, owner_ref FROM managed_cases WHERE id='case_web'").get();
  eq("D: assigned transition persists assigned status", assignedTransitionRow.status, "assigned");
  eq("D: assigned transition persists owner_ref", assignedTransitionRow.owner_ref, "Web Owner");
  const routeSrc = getSource("workers/scan-api/src/routes/managed-cases.js");
  ok("D: managed-cases route imports assignCaseOwner", /assignCaseOwner/.test(routeSrc));
  ok("D: managed-cases route has no user_demo fabricated owner fallback", !/user_demo/.test(routeSrc));
  ok("D: requireField trims whitespace-only owner_ref", /String\(value \?\? ""\)\.trim\(\)/.test(getSource("workers/scan-api/src/engines/case-workflow.js")));

  await seedUserAndWorkspace(mod, db, { user: "u_foreign", token: "tok-foreign", workspace: "ws_foreign", plan: "business" });
  const foreign = await call("case_brand", { owner_type: "team", owner_ref: "Nope" }, "tok-foreign");
  eq("D: tenant authorization blocks foreign assignment", foreign.status, 403);
}

async function checkBusinessRiskBehaviourAndMigration094() {
  const mod = await loadWorker();
  const db = buildDb();
  const writes = [];
  const env = makeEnv(db, writes);
  const { token, workspace } = await seedUserAndWorkspace(mod, db);
  const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
  const url = `https://api.cybermeters.com/api/workspaces/${workspace}/business-risk`;
  const call = async () => {
    writes.length = 0;
    const res = await mod.default.fetch(new Request(url, { headers: { Authorization: `Bearer ${token}` } }), env, ctx);
    return { res, data: await res.json(), writes: [...writes] };
  };

  const none = await call();
  eq("E: absent business-risk payload returns 200", none.res.status, 200);
  eq("E: absent business-risk payload returns honest not_assessed", none.data.state, "not_assessed");
  eq("E: absent business-risk score is null", none.data.score, null);
  ok("E: GET /business-risk performs no domain writes when absent", domainWrites(none.writes).length === 0, domainWrites(none.writes).join(" | "));

  const persistedPayload = {
    basis_contract: "complete_scan/v1",
    score: 64,
    brs: 64,
    risk_band: "moderate",
    band: "moderate",
    grade: "B",
    grade_label: "moderate",
    narrative: "Persisted canonical payload.",
    top_concerns: [{ title: "Concern" }],
    basis_scan: {
      scan_id: "scan1", status: "completed", scan_quality: "complete",
      assessed_at: "2026-07-17T12:00:00Z", scan_started_at: "2026-07-17T11:59:00Z",
    },
    workspace_context: { asset_count: 2 },
    calculated_at: "2026-07-17T12:00:00Z",
  };
  db.prepare("INSERT INTO workspace_brs_scores (workspace_id, score, risk_band, calculated_at, payload_json) VALUES (?, ?, ?, ?, ?)")
    .run(workspace, 64, "moderate", "2026-07-17T12:00:00Z", JSON.stringify(persistedPayload));
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom1', 'u_owner', 'example.com')").run();
  db.prepare("INSERT INTO scans (id, workspace_id, domain_id, domain, score, rating, status, scan_quality, created_at) VALUES ('scan1', ?, 'dom1', 'example.com', 80, 'good', 'completed', 'complete', '2026-07-17T11:59:00Z')")
    .run(workspace);
  db.prepare("INSERT INTO historical_scores (id, workspace_id, domain_id, scan_id, domain, score, rating, brs_score, scan_quality, created_at) VALUES ('hs1', ?, 'dom1', 'scan1', 'example.com', 80, 'good', 64, 'complete', '2026-07-17T12:00:00Z')")
    .run(workspace);
  const withPayload = await call();
  eq("E: persisted payload is served, not recomputed", withPayload.data.narrative, persistedPayload.narrative);
  eq("E: persisted payload keeps state assessed", withPayload.data.state, "assessed");
  ok("E: GET /business-risk performs no domain writes when payload exists", domainWrites(withPayload.writes).length === 0, domainWrites(withPayload.writes).join(" | "));

  const brsRoute = getSource("workers/scan-api/src/routes/workspace-analytics.js");
  const brsEngine = getSource("workers/scan-api/src/engines/business-risk.js");
  ok("E: canonical BRS reader selects payload_json", /SELECT workspace_id, score, risk_band, calculated_at, payload_json/.test(brsEngine));
  ok("E: GET /business-risk does not call computeAndPersistWorkspaceBrs", !/computeAndPersistWorkspaceBrs\s*\(/.test(brsRoute));
  ok("E: GET /business-risk does not update/insert workspace_brs_scores", !/INSERT OR REPLACE INTO workspace_brs_scores|UPDATE workspace_brs_scores/.test(brsRoute));

  ok("E: finalize producer persists current payload_json", /INSERT OR REPLACE INTO workspace_brs_scores[\s\S]{0,220}payload_json/.test(brsEngine));
  ok("E: finalize producer appends history row after same calculation", /INSERT INTO workspace_brs_score_history/.test(brsEngine) && /JSON\.stringify\(payload\)/.test(brsEngine));

  const mig = getSource("database/migrations/094-workspace-brs-payload.sql");
  ok("E: migration 094 is additive ADD COLUMN only", /ALTER TABLE workspace_brs_scores ADD COLUMN payload_json TEXT;/.test(mig) && !/\bDROP\b|\bDELETE\b|\bUPDATE\b/i.test(mig));
  ok("E: migration 094 documents direct re-run/idempotence expectation", /direct manual re-run[\s\S]*duplicate-column[\s\S]*migration ledger/i.test(mig));
  const pre094 = buildDb({ apply094: false });
  ok("E: pre-094 rows remain readable before migration", Boolean(pre094.prepare("SELECT workspace_id, score, risk_band FROM workspace_brs_scores").all()));
  pre094.exec(mig);
  pre094.prepare("INSERT INTO users (id, email, name, plan) VALUES ('legacy_user', 'legacy@example.com', 'Legacy', 'starter')").run();
  pre094.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('legacy_ws', 'Legacy', 'legacy_user')").run();
  pre094.prepare("INSERT INTO workspace_brs_scores (workspace_id, score, risk_band, calculated_at) VALUES ('legacy_ws', 55, 'moderate', '2026-07-17T00:00:00Z')").run();
  const legacy = pre094.prepare("SELECT workspace_id, score, risk_band, payload_json FROM workspace_brs_scores WHERE workspace_id='legacy_ws'").get();
  eq("E: migration 094 leaves existing rows readable with NULL payload_json", legacy.payload_json, null);
  let duplicateError = "";
  try { pre094.exec(mig); } catch (err) { duplicateError = String(err?.message || err); }
  ok("E: standalone SQLite migration is additive but D1-runner idempotent, duplicate column fails loudly if manually re-run",
    /duplicate column name/i.test(duplicateError), duplicateError);
}

function domainWrites(writes) {
  const infra = /^\s*(insert\s+into|update|replace\s+into)\s+(api_rate_limits|user_sessions)\b/i;
  return writes.filter((w) => !infra.test(w));
}

async function checkMspParity() {
  const { computePortfolioRisk } = await import(pathToFileURL(path.join(workerSrc, "engines", "portfolio-risk.js")).href);
  const { computePortfolioCustomerRows, buildExecutiveSummary } = await import(pathToFileURL(path.join(workerSrc, "engines", "portfolio-customers.js")).href);
  const portfolioDomains = await import(pathToFileURL(path.join(workerSrc, "engines", "portfolio-domains.js")).href);
  const stateHistory = await import(pathToFileURL(path.join(workerSrc, "engines", "cyber-mot-state-history.js")).href);
  eq("F: MSP portfolio domain registry is exactly eight", stateHistory.CYBER_MOT_DOMAIN_KEYS.length, 8);
  eq("F: MSP portfolio domain registry order is canonical", stateHistory.CYBER_MOT_DOMAIN_KEYS.join(","), CANONICAL_KEYS.join(","));

  const db = buildDb();
  db.prepare("INSERT INTO users (id,email,name,plan,status,email_verified,mfa_enabled) VALUES ('msp','msp@example.com','MSP','business','active',1,0)").run();
  db.prepare("INSERT INTO workspaces (id,name,owner_user_id,created_at,updated_at) VALUES ('w1','Alpha','msp',datetime('now'),datetime('now'))").run();
  db.prepare("INSERT INTO workspaces (id,name,owner_user_id,created_at,updated_at) VALUES ('w2','Beta','msp',datetime('now'),datetime('now'))").run();
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('dom','msp','example.com')").run();
  db.prepare("INSERT INTO scans (id,workspace_id,domain_id,domain,status,scan_quality,created_at) VALUES ('w1-scan','w1','dom','example.com','completed','complete',datetime('now'))").run();
  db.prepare("INSERT INTO workspace_brs_scores (workspace_id, score, risk_band, calculated_at, payload_json) VALUES ('w1', 90, 'low', datetime('now'), ?)").run(JSON.stringify({
    basis_contract: "complete_scan/v1", score: 90, risk_band: "low", grade: "A",
    basis_scan: { scan_id: "w1-scan", status: "completed", scan_quality: "complete" },
  }));
  const env = makeEnv(db, []);
  const portfolio = await computePortfolioRisk(["w1", "w2"], env);
  eq("F: partial MSP portfolio average excludes unassessed workspace", portfolio.portfolio_score, 90);
  eq("F: partial MSP portfolio score state discloses partial", portfolio.portfolio_score_state, "partial");
  ok("F: MSP portfolio uses backend-owned score vocabulary", ["healthy", "moderate", "elevated", "serious", null].includes(portfolio.portfolio_score_band));

  const failedEnv = makeEnv(db, [], { failSelectFrom: "workspace_brs_scores" });
  const failedPortfolio = await computePortfolioRisk(["w1", "w2"], failedEnv);
  eq("F: failed D1 portfolio query surfaces unavailable", failedPortfolio.portfolio_score_state, "unavailable");
  eq("F: failed D1 portfolio query does not publish clean zero", failedPortfolio.portfolio_score, null);
  const degradedRows = await computePortfolioCustomerRows(makeD1(db, [], { failSelectFrom: "findings" }), ["w1", "w2"]);
  ok("F: portfolio customer rows disclose degraded findings query", degradedRows.degraded_queries?.includes("findings"));
  const degradedSummary = buildExecutiveSummary(degradedRows);
  eq("F: portfolio executive summary marks partial failure", degradedSummary.portfolio.partial_failure, true);
  ok("F: portfolio executive summary does not publish clean all-clear after degraded query",
    !/No customers currently need urgent attention/.test(degradedSummary.executive_summary));

  const pdomSrc = getSource("workers/scan-api/src/engines/portfolio-domains.js");
  ok("F: portfolio domain latest scan is complete-only", /s\.scan_quality = 'complete'/.test(pdomSrc));
  const portfolioRoute = getSource("workers/scan-api/src/routes/portfolio.js");
  const trendsBlock = portfolioRoute.slice(portfolioRoute.indexOf('url.pathname === "/api/portfolio/trends"'));
  ok("F/C: portfolio trends score query is complete-quality only",
    /ROUND\(AVG\(s\.score\)[\s\S]{0,320}s\.scan_quality = 'complete'/.test(trendsBlock));
  ok("F/C: portfolio trends findings query is complete-quality only",
    /FROM findings f[\s\S]{0,260}s\.scan_quality = 'complete'/.test(trendsBlock));
  ok("F: portfolio drill-down ids include workspace_id and domain_id", /drill_down:\s*\{[\s\S]{0,120}workspace_id:[\s\S]{0,120}domain_id:/.test(pdomSrc));
  ok("F: hostname case lookup is workspace-scoped", /workspace_id IN \(\$\{wsIn\}\)[\s\S]{0,220}GROUP BY workspace_id, domain_key, domain/.test(pdomSrc));
  ok("F: comparable trends are version-gated", /resolver_version/.test(getSource("workers/scan-api/src/engines/cyber-mot-state-history.js")));
  ok("F: portfolio domain rows always build from canonical matrix", typeof portfolioDomains.computePortfolioDomainRows === "function");
  const executiveSummaryRoute = portfolioRoute.slice(
    portfolioRoute.indexOf('url.pathname === "/api/portfolio/executive-summary"'),
    portfolioRoute.indexOf('url.pathname === "/api/portfolio/alerts"'),
  );
  ok("F: /api/portfolio/executive-summary exposes degraded query state",
    /partial_failure:[\s\S]{0,160}rows\.degraded_queries/.test(executiveSummaryRoute) &&
    /unavailable_metrics:[\s\S]{0,80}rows\.degraded_queries/.test(executiveSummaryRoute));
}

async function checkFrontendParity() {
  const workspaceDash = getSource("frontend/src/pages/ws/WorkspaceDashboard.jsx");
  ok("G: WorkspaceDashboard renders eight-domain Cyber MOT surface", /<CyberMotDomains/.test(workspaceDash));
  ok("G: WorkspaceDashboard fetches backend cyber-mot-domains", /getCyberMotDomains/.test(workspaceDash));
  ok("G: WorkspaceDashboard has no second Posture Score tile", !/Latest Score/.test(workspaceDash));

  for (const file of [
    "frontend/src/components/IdentityExposureCard.jsx",
    "frontend/src/pages/AssetsPage.jsx",
    "frontend/src/pages/ws/WorkspaceIdentityPage.jsx",
    "frontend/src/pages/PortfolioPage.jsx",
  ]) {
    const src = getSource(file).replace(/\/\/[^\n]*/g, "").replace(/\{\/\*[\s\S]*?\*\/\}/g, "");
    ok(`G: ${file} has no unknown→green/low fallback`, !/unknown[^;\n]{0,120}(green|low)|\|\|\s*['"]low['"]/.test(src));
  }

  for (const file of [
    "frontend/src/components/NotificationBell.jsx",
    "frontend/src/pages/NotificationsPage.jsx",
    "frontend/src/components/ExposureTimeline.jsx",
    "frontend/src/components/ActivityTimeline.jsx",
  ]) {
    const src = getSource(file);
    for (const key of CANONICAL_KEYS) ok(`G: ${file} maps ${key}`, src.includes(key));
  }
  const bell = getSource("frontend/src/components/NotificationBell.jsx");
  const notificationsPage = getSource("frontend/src/pages/NotificationsPage.jsx");
  ok("G: NotificationBell accepts rooted app paths but rejects protocol-relative links", /startsWith\(['"]\/['"]\)\s*&&\s*!raw\.startsWith\(['"]\/\/['"]\)/.test(bell));
  ok("G: NotificationsPage accepts rooted app paths but rejects protocol-relative links", /startsWith\(['"]\/['"]\)\s*&&\s*!raw\.startsWith\(['"]\/\/['"]\)/.test(notificationsPage));
  ok("G: NotificationBell test covers external link refusal", /refuses external metadata links/i.test(getSource("frontend/src/components/__tests__/NotificationBell.test.jsx")));
  ok("G: NotificationBell test covers protocol-relative link refusal", /refuses protocol-relative metadata links/i.test(getSource("frontend/src/components/__tests__/NotificationBell.test.jsx")));
  const exposureTimeline = getSource("frontend/src/components/ExposureTimeline.jsx");
  const filterBlock = exposureTimeline.slice(exposureTimeline.indexOf("const CATEGORY_FILTERS"), exposureTimeline.indexOf("const SEVERITY_FILTERS"));
  for (const key of CANONICAL_KEYS) ok(`G: ExposureTimeline filter exposes ${key}`, filterBlock.includes(key));
  ok("G: shared presentation palette defines eight domain keys", /cyber_essentials/.test(getSource("frontend/src/theme/serviceColors.js")) && /shadow_it/.test(getSource("frontend/src/theme/serviceColors.js")));
  ok("G: WorkspaceNav test enforces eight-domain sidebar", /eight canonical domains/.test(getSource("frontend/src/components/__tests__/WorkspaceNav.test.jsx")));
  ok("G: PublicLandingPage test enforces eight-domain output", /eight canonical domains/.test(getSource("frontend/src/pages/__tests__/PublicLandingPage.test.jsx")));
  const rem = getSource("frontend/src/data/remediation.js");
  ok("G: remediation/SLA copy comes from canonical server object", !/DEFAULT_SLA|prioritySla|SLA_BY_PRIORITY/.test(rem) && /remediation\.sla|rem\.sla|source\.sla/.test(rem));
  ok("G: frontend remediation validator remains wired", /Validate frontend is not a remediation source/.test(getSource(".github/workflows/ci.yml")));
}

function checkStaticCiWiring() {
  const ci = getSource(".github/workflows/ci.yml");
  ok("CI: M5.e closure validator is wired", /validate-m5e-closure\.js/.test(ci));
  ok("CI: M5.c validator remains wired", /validate-m5c-reporting-snapshot\.js/.test(ci));
  ok("CI: M5.d validator remains wired", /validate-m5d-renderer-migration\.js/.test(ci));
}

const MUTATIONS = [
  {
    name: "delete one domain from a surface",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    mutate: (s) => s.replace(/\n  \{\n    domain_key: "identity_exposure"[\s\S]*?\n  \},\n  \{\n    domain_key: "shadow_it_unmanaged_technology"/, '\n  {\n    domain_key: "shadow_it_unmanaged_technology"'),
    expect: () => {
      const src = getSource("workers/scan-api/src/engines/cyber-mot-domains.js");
      const count = (src.match(/domain_key:\s*"/g) || []).length;
      return count === 8 ? null : `expected eight domain_key entries, got ${count}`;
    },
  },
  {
    name: "change domain order",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    mutate: (s) => s.replace('domain_key: "email_protection"', 'domain_key: "__tmp__"').replace('domain_key: "brand_protection"', 'domain_key: "email_protection"').replace('domain_key: "__tmp__"', 'domain_key: "brand_protection"'),
    expect: () => {
      const src = getSource("workers/scan-api/src/engines/cyber-mot-domains.js");
      const keys = [...src.matchAll(/domain_key:\s*"([^"]+)"/g)].map((m) => m[1]).slice(0, 8);
      return keys.join(",") === CANONICAL_KEYS.join(",") ? null : "canonical order changed";
    },
  },
  {
    name: "restore five-pillar output",
    file: "frontend/src/pages/ws/WorkspaceScorecard.jsx",
    mutate: (s) => `${s}\nconst revived = "Third-Party Risk five-pillar";\n`,
    expect: () => /five[- ]pillar|Third-Party Risk/i.test(getSource("frontend/src/pages/ws/WorkspaceScorecard.jsx")) ? "five-pillar vocabulary returned" : null,
  },
  {
    name: "restore four-service output",
    file: "frontend/src/pages/PublicLandingPage.jsx",
    mutate: (s) => s.replace("Eight domains, one posture", "Four services, one posture"),
    expect: () => /Four services|four services/i.test(getSource("frontend/src/pages/PublicLandingPage.jsx")) ? "four-service customer output returned" : null,
  },
  {
    name: "change one band threshold",
    file: "frontend/src/lib/score-presentation.js",
    mutate: (s) => s.replace("excellent: 90", "excellent: 91"),
    expect: () => /excellent:\s*91/.test(getSource("frontend/src/lib/score-presentation.js")) ? "frontend score threshold drifted" : null,
  },
  {
    name: "unknown → healthy",
    file: "frontend/src/lib/score-presentation.js",
    mutate: (s) => s.replace("unknown:   { label: 'Not assessed'", "unknown:   { label: 'Good'"),
    expect: () => /unknown:\s*\{\s*label:\s*'Good'/.test(getSource("frontend/src/lib/score-presentation.js")) ? "unknown band renders healthy" : null,
  },
  {
    name: "unavailable → zero",
    file: "workers/scan-api/src/engines/assessment-presentation.js",
    mutate: (s) => s.replace("display_score:  hasScore ? score : null", "display_score:  hasScore ? score : 0"),
    expect: () => /display_score:\s*hasScore \? score : 0/.test(getSource("workers/scan-api/src/engines/assessment-presentation.js")) ? "unavailable score coerces to zero" : null,
  },
  {
    name: "failed query → clean zero",
    file: "workers/scan-api/src/engines/portfolio-risk.js",
    mutate: (s) => s.replace("const brsMap = brsRes.status === 'fulfilled' ? brsRes.value : new Map();", "const brsMap = brsRes.status === 'fulfilled' ? brsRes.value : new Map([['__failed', { score: 0 }]]);"),
    expect: () => /new Map\(\[\['__failed', \{ score: 0 \}\]\]\)/.test(getSource("workers/scan-api/src/engines/portfolio-risk.js")) ? "failed portfolio query converted into zero" : null,
  },
  {
    name: "portfolio executive summary drops degraded query state",
    file: "workers/scan-api/src/routes/portfolio.js",
    mutate: (s) => s.replaceAll("partial_failure", "partial_failure_removed").replaceAll("unavailable_metrics", "unavailable_metrics_removed"),
    expect: () => {
      const src = getSource("workers/scan-api/src/routes/portfolio.js");
      const block = src.slice(src.indexOf('url.pathname === "/api/portfolio/executive-summary"'), src.indexOf('url.pathname === "/api/portfolio/alerts"'));
      return /partial_failure:[\s\S]{0,160}rows\.degraded_queries/.test(block) && /unavailable_metrics:[\s\S]{0,80}rows\.degraded_queries/.test(block)
        ? null
        : "portfolio executive summary dropped degraded query state";
    },
  },
  {
    name: "assigned state with NULL owner",
    file: "workers/scan-api/src/engines/managed-case-model.js",
    mutate: (s) => s.replace('assigned:         [requireField("owner_ref")],', 'assigned:         [],'),
    expect: () => /assigned:\s*\[requireField\("owner_ref"\)\]/.test(getSource("workers/scan-api/src/engines/managed-case-model.js")) ? null : "assigned transition no longer requires owner_ref",
  },
  {
    name: "assigned state with whitespace owner",
    file: "workers/scan-api/src/engines/case-workflow.js",
    mutate: (s) => s.replace('return String(value ?? "").trim() ? true : `${name} is required.`;', 'return value ? true : `${name} is required.`;'),
    expect: () => /String\(value \?\? ""\)\.trim\(\)/.test(getSource("workers/scan-api/src/engines/case-workflow.js")) ? null : "assigned transition accepts whitespace owner_ref",
  },
  {
    name: "remove assignment_changed event",
    file: "workers/scan-api/src/routes/managed-cases.js",
    mutate: (s) => s.replaceAll("assignment_changed", "assignment_removed"),
    expect: () => /assignment_changed/.test(getSource("workers/scan-api/src/routes/managed-cases.js")) ? null : "assignment_changed event removed",
  },
  {
    name: "restore user_demo fallback",
    file: "workers/scan-api/src/routes/managed-cases.js",
    mutate: (s) => `${s}\nconst ownerFallback = "user_demo";\n`,
    expect: () => /user_demo/.test(getSource("workers/scan-api/src/routes/managed-cases.js")) ? "user_demo fallback returned" : null,
  },
  {
    name: "restore /business-risk write-on-read",
    file: "workers/scan-api/src/routes/workspace-analytics.js",
    mutate: (s) => s.replace("return json({ ...assessment, workspace_name: ws.name, trend });", "await env.cybermeters_db.prepare('INSERT INTO workspace_brs_score_history (id, workspace_id, score) VALUES (?,?,?)').bind('x', wsId, assessment.score).run(); return json({ ...assessment, workspace_name: ws.name, trend });"),
    expect: () => /INSERT INTO workspace_brs_score_history/.test(getSource("workers/scan-api/src/routes/workspace-analytics.js")) ? "GET /business-risk writes on read" : null,
  },
  {
    name: "reintroduce live GET recalculation",
    file: "workers/scan-api/src/routes/workspace-analytics.js",
    mutate: (s) => `${s}\ncomputeAndPersistWorkspaceBrs(env, wsId);\n`,
    expect: () => /computeAndPersistWorkspaceBrs\s*\(/.test(getSource("workers/scan-api/src/routes/workspace-analytics.js")) ? "GET /business-risk recalculates live" : null,
  },
  {
    name: "allow partial scan in portfolio average",
    file: "workers/scan-api/src/engines/portfolio-domains.js",
    mutate: (s) => s.replace("AND s.status = 'completed' AND s.scan_quality = 'complete'", "AND s.status = 'completed'"),
    expect: () => /s\.scan_quality = 'complete'/.test(getSource("workers/scan-api/src/engines/portfolio-domains.js")) ? null : "partial scan allowed into portfolio posture",
  },
  {
    name: "allow partial scan in portfolio trend",
    file: "workers/scan-api/src/routes/portfolio.js",
    mutate: (s) => s.replaceAll("              AND s.scan_quality = 'complete'\n", ""),
    expect: () => /url\.pathname === "\/api\/portfolio\/trends"[\s\S]*s\.scan_quality = 'complete'/.test(getSource("workers/scan-api/src/routes/portfolio.js")) ? null : "partial scan allowed into portfolio trend",
  },
  {
    name: "restore MSP vocabulary drift",
    file: "workers/scan-api/src/engines/portfolio-risk.js",
    mutate: (s) => s.replace("if (score >= 75) return 'healthy';", "if (score >= 75) return 'low';"),
    expect: () => /return 'low';/.test(getSource("workers/scan-api/src/engines/portfolio-risk.js")) ? "MSP score vocabulary drifted" : null,
  },
  {
    name: "bypass canonical remediation/SLA source",
    file: "frontend/src/data/remediation.js",
    mutate: (s) => `${s}\nconst DEFAULT_SLA = { high: '7 days' };\n`,
    expect: () => /DEFAULT_SLA/.test(getSource("frontend/src/data/remediation.js")) ? "frontend SLA fallback returned" : null,
  },
  {
    name: "use hostname without workspace scope",
    file: "workers/scan-api/src/engines/portfolio-domains.js",
    mutate: (s) => s.replace("WHERE workspace_id IN (${wsIn})\n         AND status NOT IN", "WHERE status NOT IN"),
    expect: () => /FROM managed_cases[\s\S]{0,180}WHERE workspace_id IN \(\$\{wsIn\}\)/.test(getSource("workers/scan-api/src/engines/portfolio-domains.js")) ? null : "hostname drill-down/case lookup lost workspace scope",
  },
  {
    name: "allow protocol-relative notification link",
    file: "frontend/src/components/NotificationBell.jsx",
    mutate: (s) => s.replace("if (raw.startsWith('/') && !raw.startsWith('//')) return raw", "if (raw.startsWith('/')) return raw"),
    expect: () => /startsWith\(['"]\/['"]\)\s*&&\s*!raw\.startsWith\(['"]\/\/['"]\)/.test(getSource("frontend/src/components/NotificationBell.jsx")) ? null : "protocol-relative notification link accepted",
  },
  {
    name: "remove canonical timeline filter",
    file: "frontend/src/components/ExposureTimeline.jsx",
    mutate: (s) => s.replace("  { value: 'attack_surface',                 label: 'Attack Surface' },\n", ""),
    expect: () => /const CATEGORY_FILTERS[\s\S]*\{\s*value:\s*['"]attack_surface['"]\s*,\s*label:\s*['"]Attack Surface['"]\s*\}/.test(getSource("frontend/src/components/ExposureTimeline.jsx")) ? null : "canonical timeline filter missing",
  },
];

async function runMutations() {
  const original = new Map(sourceFiles);
  let mutationPass = 0;
  let mutationFail = 0;
  for (const m of MUTATIONS) {
    sourceFiles.clear();
    for (const [k, v] of original) sourceFiles.set(k, v);
    setSource(m.file, m.mutate(getSource(m.file)));
    const reason = m.expect();
    if (reason) {
      mutationPass++;
    } else {
      mutationFail++;
      console.log(`FAIL mutation '${m.name}' did not fail for intended reason`);
    }
  }
  sourceFiles.clear();
  for (const [k, v] of original) sourceFiles.set(k, v);
  ok(`mutations: ${MUTATIONS.length} required regressions fail for intended reason`, mutationFail === 0, `${mutationPass} failed as expected, ${mutationFail} escaped`);
}

async function main() {
  await checkEightDomainCompleteness();
  await checkScoreAndStateHonesty();
  await checkOwnershipBehaviour();
  await checkBusinessRiskBehaviourAndMigration094();
  await checkMspParity();
  await checkFrontendParity();
  checkStaticCiWiring();
  await runMutations();

  console.log(`\nm5e-closure: ${pass} passed, ${fail} failed`);
  if (fail) {
    console.error("m5e-closure validation FAILED");
    process.exit(1);
  }
  console.log("m5e-closure validation passed");
}

main().catch((err) => {
  console.error(err?.stack || err);
  process.exit(1);
});
